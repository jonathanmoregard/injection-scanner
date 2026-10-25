"""
Layer 2 adapter: Google Cloud Model Armor, FAIL-CLOSED.

One member of the L2 panel (`injection_scanner.l2`). This module owns only
what is Model Armor's: the service-account credential and its OAuth token,
the endpoint built from validated ids, the size cap, the monthly token
budget, the request payload and the strict response parse. Transport,
pacing and transport-failure reasons are `injection_scanner.vendor_http`'s;
the token exchange goes through the same hardened opener, unpaced.

Order, each step before anything that costs more:
  1. credential (`keyloader`: FILE > env > keyring) — `no-key` /
     `key-config-error`;
  2. endpoint from `MODEL_ARMOR_PROJECT` / `_LOCATION` / `_TEMPLATE` —
     `url-config-error`; the URL is BUILT here, never read from the
     environment, and checked against the exact destination;
  3. size cap — `too-large`, never sent (unavailable, never a pass);
  4. OAuth access token, cached in process — `token-error[:<status>]`;
  5. limiter, then a monthly-budget reservation (`vendor_http.paced_post`'s
     `before_send`), so a call the limiter refuses spends no budget; the
     reservation is kept only for a decoded HTTP 200 and released otherwise
     (`_Spend`);
  6. strict parse of the `pi_and_jailbreak` filter result.

Steps 1-2 are `_preflight`, shared with `ready()` (boot readiness), so boot
refuses on exactly what a scan would, without any network call.

Invariant 4 ("the caught bytes never return"): `reason` carries only fixed
labels, exception TYPE names and a bounded HTTP status — never the text, the
credential, the token, or anything Model Armor said (`sanitizationMetadata`
is never read).
"""
from __future__ import annotations

import base64
import json
import math
import os
import re
import time
import urllib.parse
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from injection_scanner import vendor_http
from injection_scanner.keyloader import KeyConfigError, load_key
from injection_scanner.throttle import (
    DEFAULT_LOCK_WAIT_S,
    ENV_LOCK_WAIT_S,
    LOCK_WAIT_RANGE,
    Decision,
    MonthlyBudget,
    Reservation,
    cache_dir,
    env_float,
    env_int,
    vendor_env,
)
from injection_scanner.vendor_http import VendorResult

VENDOR = "model_armor"

ENV_CREDENTIALS_FILE = "MODEL_ARMOR_CREDENTIALS_FILE"
ENV_CREDENTIALS = "MODEL_ARMOR_CREDENTIALS"
KEYRING_KEY = "model-armor-sa-key"
ENV_PROJECT = "MODEL_ARMOR_PROJECT"
ENV_LOCATION = "MODEL_ARMOR_LOCATION"
ENV_TEMPLATE = "MODEL_ARMOR_TEMPLATE"

TOKEN_URI = "https://oauth2.googleapis.com/token"
SCOPE = "https://www.googleapis.com/auth/cloud-platform"

# Google's own id grammars, as strict full matches. `location` covers regions
# (`europe-west4`) and multi-regions (`eu`, `us`).
_PROJECT = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]\Z")
_LOCATION = re.compile(r"[a-z]+(-[a-z]+[0-9]+)?\Z")
_TEMPLATE = re.compile(r"[A-Za-z0-9_-]{1,63}\Z")

# The prompt-injection filter accepts up to 65,536 tokens. The size cap is a
# character count: 240,000 sits under 65,536 tokens at Google's ~4 characters
# per token, and above the largest research report seen (~95k characters).
# The ceiling is that token limit in characters; the floor keeps a typo from
# turning every report into `too-large`.
ENV_MAX_CHARS = "MAX_CHARS"
DEFAULT_MAX_CHARS = 240_000
MAX_CHARS_RANGE = (1_000, 262_144)

# The free tier is 2M tokens a month and nothing server-side stops a project
# past it: it is billed instead, at $0.10 per 1M tokens. The fleet scans about
# 1.5M tokens a month, so a cap at the free tier would refuse scans late in a
# heavy month, and with a panel floor of 2 that refuses every report. The
# default is a runaway guard, not a free-tier fence: 20M tokens is at most
# ~$1.80 a month over the free tier. 0 refuses every call.
ENV_MONTHLY_TOKENS = "MONTHLY_TOKENS"
DEFAULT_MONTHLY_TOKENS = 20_000_000
MONTHLY_TOKENS_RANGE = (0, 100_000_000)

# A cached token is replaced this long before Google says it expires, so a
# request never leaves with a token that dies in flight.
_REFRESH_MARGIN_S = 300.0
# JWT assertion lifetime; Google accepts at most one hour.
_ASSERTION_LIFETIME_S = 3600
# RFC 6750 `b64token`, bounded: the token goes into a header verbatim.
_ACCESS_TOKEN = re.compile(r"[A-Za-z0-9._~+/-]{1,4096}=*\Z")
_EXPIRES_IN_RANGE = (1, 86_400)


def max_chars() -> int:
    return env_int(vendor_env(VENDOR, ENV_MAX_CHARS), DEFAULT_MAX_CHARS, MAX_CHARS_RANGE)


def monthly_tokens() -> int:
    return env_int(
        vendor_env(VENDOR, ENV_MONTHLY_TOKENS),
        DEFAULT_MONTHLY_TOKENS,
        MONTHLY_TOKENS_RANGE,
    )


def estimate_tokens(text: str) -> int:
    """Google's billing estimate: non-whitespace code points / 4, rounded up."""
    return math.ceil(sum(1 for c in text if not c.isspace()) / 4)


def _unavailable(condition: str) -> VendorResult:
    return vendor_http.unavailable(VENDOR, condition)


# ---------- credential ----------


@dataclass(frozen=True)
class _Credential:
    """A parsed service-account key. No field is ever rendered."""

    client_email: str = field(repr=False)
    private_key_id: str = field(repr=False)
    private_key: rsa.RSAPrivateKey = field(repr=False)

    @property
    def identity(self) -> tuple[str, str]:
        return (self.client_email, self.private_key_id)


def _nonempty_str(obj: dict, key: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise KeyConfigError
    return value


def _credential() -> _Credential | None:
    """The service-account key, or None when none is configured.

    Raises KeyConfigError for a configured source that is broken or is not
    a service-account key whose `token_uri` is exactly Google's. The error
    carries no field of the key; the caller renders the fixed literal.
    """
    raw = load_key(
        file_env=ENV_CREDENTIALS_FILE,
        env_var=ENV_CREDENTIALS,
        keyring_key=KEYRING_KEY,
    )
    if not raw:
        return None
    try:
        obj = vendor_http.strict_json_loads(raw)
    except Exception:  # noqa: BLE001 — any parse failure is the same misconfig
        raise KeyConfigError from None
    if not isinstance(obj, dict):
        raise KeyConfigError
    if obj.get("type") != "service_account" or obj.get("token_uri") != TOKEN_URI:
        raise KeyConfigError
    email = _nonempty_str(obj, "client_email")
    key_id = _nonempty_str(obj, "private_key_id")
    pem = _nonempty_str(obj, "private_key")
    try:
        key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    except Exception:  # noqa: BLE001 — never echo why; the key is the secret
        raise KeyConfigError from None
    if not isinstance(key, rsa.RSAPrivateKey):
        raise KeyConfigError
    return _Credential(client_email=email, private_key_id=key_id, private_key=key)


# ---------- endpoint ----------


def _endpoint() -> tuple[str, str, str] | None:
    """(project, location, template), or None if any is missing or invalid."""
    ids = []
    for name, grammar in (
        (ENV_PROJECT, _PROJECT),
        (ENV_LOCATION, _LOCATION),
        (ENV_TEMPLATE, _TEMPLATE),
    ):
        value = os.environ.get(name, "")
        if not grammar.match(value):
            return None
        ids.append(value)
    project, location, template = ids
    return project, location, template


def _url(project: str, location: str, template: str) -> str:
    return (
        f"https://modelarmor.{location}.rep.googleapis.com/v1/projects/{project}"
        f"/locations/{location}/templates/{template}:sanitizeUserPrompt"
    )


def _is_trusted_endpoint(url: str, project: str, location: str, template: str) -> bool:
    """True only for the exact `sanitizeUserPrompt` destination of these ids.

    The ids are already validated and the URL is built from them, so this is
    the second, independent statement of where the bearer token may go: one
    host (`modelarmor.<location>.rep.googleapis.com`), default port, no
    credentials, one path, no query or fragment.
    """
    if not isinstance(url, str) or not url.isascii():
        return False
    try:
        parsed = urllib.parse.urlsplit(url)
        host = f"modelarmor.{location}.rep.googleapis.com"
        return (
            parsed.scheme == "https"
            and parsed.netloc == host
            and parsed.hostname == host
            and parsed.port is None
            and parsed.username is None
            and parsed.password is None
            and parsed.path
            == f"/v1/projects/{project}/locations/{location}/templates/{template}"
            ":sanitizeUserPrompt"
            and not parsed.query
            and not parsed.fragment
            and "?" not in url
            and "#" not in url
        )
    except (TypeError, ValueError):
        return False


# ---------- OAuth token ----------


class _TokenFailure(Exception):
    """The exchange failed. `condition` is a closed literal built here."""

    def __init__(self, condition: str) -> None:
        super().__init__()
        self.condition = condition


@dataclass(frozen=True)
class _Token:
    identity: tuple[str, str] = field(repr=False)
    value: str = field(repr=False)
    refresh_at: float


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _compact_json(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def _assertion(cred: _Credential, now: float) -> str:
    """The RS256 JWT a service account trades for an access token."""
    iat = int(now)
    header = {"alg": "RS256", "typ": "JWT", "kid": cred.private_key_id}
    claims = {
        "iss": cred.client_email,
        "scope": SCOPE,
        "aud": TOKEN_URI,
        "iat": iat,
        "exp": iat + _ASSERTION_LIFETIME_S,
    }
    signing_input = f"{_b64url(_compact_json(header))}.{_b64url(_compact_json(claims))}"
    signature = cred.private_key.sign(
        signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
    )
    return f"{signing_input}.{_b64url(signature)}"


def _parse_token(data: object) -> tuple[str, int]:
    if not isinstance(data, dict):
        raise _TokenFailure("token-error")
    token = data.get("access_token")
    expires_in = data.get("expires_in")
    if (
        not isinstance(token, str)
        or not _ACCESS_TOKEN.match(token)
        or data.get("token_type") != "Bearer"
        or type(expires_in) is not int
        or not _EXPIRES_IN_RANGE[0] <= expires_in <= _EXPIRES_IN_RANGE[1]
    ):
        raise _TokenFailure("token-error")
    return token, expires_in


class _TokenSource:
    """Mints access tokens and keeps the current one. The module's only
    mutable state: one holder, one slot, keyed by the service account so a
    rotated key never reuses its predecessor's token. `clock` is injected so
    expiry is testable; production uses wall time."""

    def __init__(self, clock=time.time) -> None:
        self._clock = clock
        self._token: _Token | None = None

    def token(self, cred: _Credential) -> str:
        now = self._clock()
        cached = self._token
        if cached is not None and cached.identity == cred.identity and now < cached.refresh_at:
            return cached.value
        value, expires_in = self._exchange(cred, now)
        self._token = _Token(
            identity=cred.identity,
            value=value,
            refresh_at=now + expires_in - _REFRESH_MARGIN_S,
        )
        return value

    def forget(self) -> None:
        self._token = None

    @staticmethod
    def _exchange(cred: _Credential, now: float) -> tuple[str, int]:
        """POST the assertion to Google's token endpoint, unpaced.

        Reasons: `token-error:<status>` for an HTTP error (a 3xx included:
        redirects are refused), bare `token-error` for any other failure or a
        malformed token response. A 429 is Google rate-limiting this project,
        the same condition as a 429 from Model Armor itself, so it is the
        quota-class `HTTPError:429`.
        """
        body = urllib.parse.urlencode(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": _assertion(cred, now),
            }
        ).encode("ascii")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        try:
            data = vendor_http.send(VENDOR, TOKEN_URI, body, headers)
        except Exception as e:  # noqa: BLE001 — fails CLOSED, type-free reason
            code = vendor_http.breaker_code(e)
            if code == 429:
                raise _TokenFailure("HTTPError:429") from None
            if code is not None:
                raise _TokenFailure(f"token-error:{code}") from None
            raise _TokenFailure("token-error") from None
        return _parse_token(data)


_TOKENS = _TokenSource()


# ---------- the check ----------


@dataclass(frozen=True)
class _Prepared:
    credential: _Credential = field(repr=False)
    url: str


def _preflight() -> _Prepared | VendorResult:
    """Everything `check` resolves before it costs anything: the credential
    (`no-key` / `key-config-error`) and the endpoint (`url-config-error`).
    Local only — no network, no limiter, no budget — so `ready` can run it
    at boot and refuse on exactly what a scan would."""
    try:
        cred = _credential()
    except KeyConfigError:
        return _unavailable("key-config-error")
    if cred is None:
        return _unavailable("no-key")
    ids = _endpoint()
    if ids is None:
        return _unavailable("url-config-error")
    url = _url(*ids)
    if not _is_trusted_endpoint(url, *ids):
        return _unavailable("url-config-error")
    return _Prepared(credential=cred, url=url)


def ready() -> str | None:
    """None if a call could be sent, else the closed reason `check` would
    return before sending. Touches no network and spends no token."""
    prepared = _preflight()
    return prepared.reason if isinstance(prepared, VendorResult) else None


class _Spend:
    """One call's monthly-budget spend: reserve, then settle.

    `reserve` runs as `paced_post`'s `before_send`, after the limiter admits
    the call: the estimate is taken under the ledger lock, so concurrent
    callers across the fleet cannot overshoot the month. `settle` keeps it
    only when Model Armor answered with a decoded HTTP 200 — the outcome it
    bills, whatever the verdict — and releases it for every other outcome, so
    a dead or erroring endpoint cannot drain the month with zero verdicts.
    A timeout is released too although Google may have billed it, so the
    ledger can under-count by such calls; a runaway guard tolerates that.
    """

    def __init__(self, cost: int) -> None:
        self._cost = cost
        self._held: Reservation | None = None

    def reserve(self) -> VendorResult | None:
        try:
            budget = MonthlyBudget(
                cache_dir(),
                VENDOR,
                monthly_tokens(),
                lock_wait_s=env_float(
                    vendor_env(VENDOR, ENV_LOCK_WAIT_S), DEFAULT_LOCK_WAIT_S, LOCK_WAIT_RANGE
                ),
            )
            self._held = budget.reserve(self._cost)
            decision = self._held.decision
        except Exception:  # noqa: BLE001 — fails CLOSED
            decision = Decision.ERROR
        if decision is Decision.ALLOWED:
            return None
        if decision is Decision.THROTTLED:
            return _unavailable("throttled")
        return _unavailable("limiter-error")

    def settle(self, reply: vendor_http.Reply) -> None:
        if self._held is not None and reply.failure is not None:
            self._held.release()


def check(text: str, *, max_wait_s: float | None = None) -> VendorResult:
    """Classify `text` with Model Armor's prompt-injection filter. FAIL-CLOSED.

    Reasons (closed vocabulary):
      * `model_armor_unavailable:no-key`           — no credential configured
      * `model_armor_unavailable:key-config-error` — credential unreadable, or
                                                     not a service-account key
                                                     for `TOKEN_URI`
      * `model_armor_unavailable:url-config-error` — project / location /
                                                     template missing or invalid
      * `model_armor_unavailable:too-large`        — over `MAX_CHARS`; not sent
      * `model_armor_unavailable:token-error[:<status>]`
                                                   — OAuth exchange failed
      * `model_armor_unavailable:throttled`        — fleet pacing, quota
                                                     breaker, or monthly budget
      * `model_armor_unavailable:limiter-error`    — limiter or budget unusable
      * `model_armor_unavailable:service-unavailable` / `:<ExcType>[:<status>]`
                                                   — see `vendor_http.paced_post`
      * `model_armor_unavailable:skipped`          — the filter did not run
      * `model_armor_unavailable:partial-invocation` — not every filter ran
      * `model_armor_unavailable:bad-response`     — unknown response shape
      * `model_armor:prompt_attack`                — `MATCH_FOUND`
      * `pass`                                     — `NO_MATCH_FOUND`

    `max_wait_s` is how long this call may wait for a fleet token; `None`
    means `INJECTION_SCANNER_MODEL_ARMOR_MAX_WAIT_S` (default 0).
    """
    prepared = _preflight()
    if isinstance(prepared, VendorResult):
        return prepared
    cred, url = prepared.credential, prepared.url

    if len(text) > max_chars():
        return _unavailable("too-large")

    try:
        token = _TOKENS.token(cred)
    except _TokenFailure as f:
        return _unavailable(f.condition)

    spend = _Spend(estimate_tokens(text))
    reply = vendor_http.paced_post(
        VENDOR,
        url,
        json.dumps({"userPromptData": {"text": text}}).encode("utf-8"),
        {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        max_wait_s=max_wait_s,
        before_send=spend.reserve,
    )
    spend.settle(reply)
    if reply.failure is not None:
        if reply.failure.reason == f"{VENDOR}_unavailable:HTTPError:401":
            # A revoked or expired token: the next call mints a fresh one.
            _TOKENS.forget()
        return reply.failure
    try:
        return _parse(reply.data)
    except Exception:  # noqa: BLE001 — hostile decoded objects fail CLOSED
        return _unavailable("bad-response")


def _parse(data: object) -> VendorResult:
    """Strict `sanitizeUserPrompt` response contract.

    `sanitizationResult.invocationResult` must be `SUCCESS` (`PARTIAL` /
    `FAILURE` -> `partial-invocation`), and
    `sanitizationResult.filterResults.pi_and_jailbreak.piAndJailbreakFilterResult`
    must carry `executionState` (`EXECUTION_SUCCESS`; `EXECUTION_SKIPPED` ->
    `skipped`) and `matchState` (`MATCH_FOUND` / `NO_MATCH_FOUND`). Other
    filters and every text field are ignored. Anything else is
    `bad-response`.
    """
    result = data.get("sanitizationResult") if isinstance(data, dict) else None
    if not isinstance(result, dict):
        return _unavailable("bad-response")
    invocation = result.get("invocationResult")
    if invocation in ("PARTIAL", "FAILURE"):
        return _unavailable("partial-invocation")
    if invocation != "SUCCESS":
        return _unavailable("bad-response")

    filters = result.get("filterResults")
    pi = filters.get("pi_and_jailbreak") if isinstance(filters, dict) else None
    pi_result = pi.get("piAndJailbreakFilterResult") if isinstance(pi, dict) else None
    if not isinstance(pi_result, dict):
        return _unavailable("bad-response")

    execution = pi_result.get("executionState")
    if execution == "EXECUTION_SKIPPED":
        return _unavailable("skipped")
    if execution != "EXECUTION_SUCCESS":
        return _unavailable("bad-response")

    match = pi_result.get("matchState")
    if match == "MATCH_FOUND":
        return VendorResult(ok=False, flagged=True, reason="model_armor:prompt_attack")
    if match == "NO_MATCH_FOUND":
        return VendorResult(ok=True, reason="pass")
    return _unavailable("bad-response")
