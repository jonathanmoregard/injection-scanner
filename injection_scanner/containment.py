"""Opaque holders for values that may embed attacker-controlled bytes.

A scanner result mixes two trust classes. Most of it (`ok`, `reason`,
`signal`, `layers`) is synthesized from a fixed vocabulary and is safe
anywhere. A few values carry text that ultimately originates in the
scanned report — directly, or laundered through a provider error body
that echoes request fragments back at us.

A plain `str` / `dict[str, str]` annotation makes those two classes look
identical at the call site, so a new consumer cannot tell which is which
without reading honeypot.py. The types here are the marker: any field
annotated with one of them is cleared for the quarantine audit file and
nothing else.

This module deliberately has no imports from the rest of the package, so
the holders can be applied at the POINT OF CONSTRUCTION — inside
`honeypot.py`, the layer that first touches provider bytes — rather than
several hops later when the `Verdict` is assembled. A wrapper applied late
leaves an unwrapped window on every public object in between; that window
was the containment hole this module closes.

They are guards, not just labels:

  * `repr` / `str` redact, so `print(result)`, an f-string, a log line, or
    a pytest assertion diff cannot spill the contents — and unlike
    `field(repr=False)`, that holds even after the value has been pulled
    off the dataclass into a local, and for containers that render their
    elements' reprs.
  * `json.dumps(..., default=str)` — the exact call the audit writer uses
    — serializes the redaction, not the payload. A structure that reaches
    a JSON encoder by some path other than `Verdict.to_audit()` fails
    closed. Without `default=`, it raises instead.
  * `QuarantineOnly` is deliberately NOT a Mapping: no `__iter__`, no
    `__getitem__`, no `.items()`. `QuarantineOnlyText` is deliberately not
    a `str` subclass, so it cannot be concatenated, formatted, or sliced
    into a message by reflex. Reading a payload requires naming
    `reveal_for_quarantine_record()`, which is unpleasant enough to read
    in a diff that it cannot happen by accident. That awkwardness is the
    point and must not be traded away for ergonomics.
  * Neither is a dataclass, so `dataclasses.asdict()` on a containing
    dataclass cannot flatten them back into raw strings.
  * `coerce()` plus the `QuarantineFieldsCoerced` mixin make the holder
    STRUCTURAL rather than conventional. Annotating a field
    `QuarantineOnly` documents the intent, but the library was still the
    only thing keeping the promise: `Verdict(..., honeypot_api_errors={...})`
    or a later `result.api_error_detail = "..."` put a bare payload back on
    a public object, and the next `repr()` spilled it. The mixin funnels
    every assignment to those fields through `coerce()`, so the wrapper is
    what the object HAS, not what its constructor was trusted to pass.
    `coerce()` is TOTAL — every value becomes a holder, including types the
    field was never meant to hold. A coercion with an escape hatch is not a
    boundary: a list or any object with a payload-bearing `__repr__` used
    to sail through untouched, which looked like containment and was not.

What they do NOT protect against — known, accepted, and listed here so
nobody mistakes these types for a hard boundary:

  * `pickle.dumps(wrapper)` emits the payload as plaintext in the pickle
    stream, and `copy.deepcopy` reads it the same way, both via
    `__reduce_ex__`. Anything that serializes objects generically — a
    cache, a task queue, `multiprocessing`, a crash dumper — therefore
    carries the raw bytes. Blocking `__reduce__` would close this, but it
    would also make `dataclasses.asdict()` on a containing dataclass raise
    instead of yielding an opaque wrapper, i.e. it would trade a rare
    exotic path for the common one the tests pin. Not worth it.
  * `wrapper._values` / `wrapper._value` is a plain attribute read.
    `__slots__` blocks new attributes, not access to these; Python has no
    private state.

So the guarantee is narrow and worth stating exactly: these types stop the
payload riding an INCIDENTAL rendering or serialization path — a repr, an
f-string, a log line, a pytest diff, a `json.dumps`. They cannot stop code
that deliberately goes after the payload. Deciding where the bytes are
allowed to go is still the caller's job; `Verdict.to_audit()` is the one
place in this package that has made that decision.
"""
from __future__ import annotations

from collections.abc import Mapping


class _OpaqueHolder:
    """Shared redaction machinery. Subclasses supply `_redaction()`,
    `_BARE_TYPES` and `_adopt_foreign()` only.

    Factored out so the two holders cannot drift: a `__repr__` that
    forgets to redact — or a `coerce()` that forgets to wrap — is the whole
    failure mode this module exists to prevent, and duplicating it twice is
    how that happens.
    """

    __slots__ = ()

    # The shapes this holder adopts NATURALLY, keeping the payload intact:
    # `str` for the text holder, `Mapping` for the mapping one. Declared per
    # subclass; the coercion itself lives here so it cannot diverge.
    # Everything else still gets wrapped, via `_adopt_foreign`.
    _BARE_TYPES: tuple[type, ...] = ()

    def _redaction(self) -> str:  # pragma: no cover - overridden
        raise NotImplementedError

    @classmethod
    def _adopt_foreign(cls, value: object) -> _OpaqueHolder:  # pragma: no cover - overridden
        raise NotImplementedError

    @staticmethod
    def _render_unexpected(value: object) -> str:
        """Render a value of an unexpected type, from INSIDE the holder.

        Deliberately a holder method rather than something a caller does
        before wrapping. `QuarantineOnlyText(repr(obj))` at a call site
        creates exactly the bare intermediate this module exists to
        prevent — a plain `str` of attacker-derived bytes, live in the
        caller's scope, one log line away from escaping. Here the string
        is born and consumed inside `_adopt_foreign` and is never returned
        to anyone.

        `repr()` is the rendering because it is what would have leaked
        anyway: an object that reaches a `print`, an f-string or
        `json.dumps(..., default=str)` is rendered by exactly this call.
        Capturing it verbatim keeps the diagnostic and moves it inside the
        holder.

        Never raises. A `__repr__` that blows up is itself a caller bug and
        must not become a scanner outage, so the exception TYPE NAME stands
        in — the same discipline the rest of the package applies to
        provider exceptions, and for the same reason: `str(e)` on a broken
        repr can carry the very bytes we are containing.
        """
        try:
            return repr(value)
        except Exception as e:  # noqa: BLE001 — a broken __repr__ is not an outage
            return f"<unrepresentable: {type(e).__name__}>"

    @classmethod
    def coerce(cls, value: object) -> _OpaqueHolder:
        """Wrap ANY value. Total by construction: the return is a holder.

        Wrap rather than reject on purpose. A `TypeError` here would only
        move the failure from "silent leak in the library" to "crash in the
        consuming server", and a scanner that crashes on a diagnostic field
        is worse than one that quietly does the safe thing. Coercion makes
        the containment automatic: there is no way to spell the unsafe
        version.

        An earlier revision returned unrecognised values untouched, which
        made the coercion look total without being it:
        `Verdict(honeypot_api_errors=["provider text"])`, or any object
        with a payload-bearing `__repr__`, stayed bare and leaked through
        `repr(v)` and `json.dumps(..., default=str)`. Passing an odd type
        through is never safer than wrapping it — these fields are
        annotated `str` / `dict[str, str]`, so an odd type is already a
        caller bug, and the only question is whether it is also a leaking
        one. There are now four outcomes and every one of them is a
        holder:

          * already this holder -> returned by identity, so the library's
            own pass-through (`hp.api_error_details` -> `Verdict`) is not
            an unwrap-and-rewrap;
          * `None` -> EMPTY holder, i.e. "absent". Not the string "None":
            that is the field's own default (`default_factory`) semantics,
            and it keeps a placeholder out of the audit record;
          * a naturally-adopted shape (`_BARE_TYPES`) -> wrapped with the
            payload intact;
          * anything else -> `_adopt_foreign`, which renders it inside the
            holder.

        Natural adoption is itself guarded. `isinstance(value, Mapping)`
        says the value claims the protocol, not that iterating it works: a
        `Mapping` whose `__iter__` raises would make this function raise and
        break the totality above. Such a value falls back to
        `_adopt_foreign`, whose rendering cannot raise either.
        """
        if isinstance(value, cls):
            return value
        if value is None:
            return cls()  # type: ignore[call-arg]
        if cls._BARE_TYPES and isinstance(value, cls._BARE_TYPES):
            try:
                return cls(value)  # type: ignore[call-arg]
            except Exception:  # noqa: BLE001 — totality outranks fidelity here
                pass
        return cls._adopt_foreign(value)

    def __repr__(self) -> str:
        return self._redaction()

    # Bound to the base `__repr__`, which dispatches through `_redaction`,
    # so subclasses stay covered without repeating this line.
    __str__ = __repr__

    __hash__ = None  # type: ignore[assignment]  # mutable / comparable payload


class QuarantineOnlyText(_OpaqueHolder):
    """Opaque holder for ONE untrusted string.

    Used for `honeypot.ScenarioResult.api_error_detail`: the structured
    provider error body, which can echo request fragments derived from the
    scanned report.
    """

    __slots__ = ("_value",)

    # A bare `str` on a field annotated with this holder is the exposure
    # `coerce()` closes; adopt it rather than leave it unwrapped.
    _BARE_TYPES = (str,)

    def __init__(self, value: str = "") -> None:
        self._value: str = value

    @classmethod
    def _adopt_foreign(cls, value: object) -> QuarantineOnlyText:
        """Wrap a non-string. One expression: no bare local to leak."""
        return cls(cls._render_unexpected(value))

    def reveal_for_quarantine_record(self) -> str:
        """Return the raw string. ONE legal destination.

        That destination is the quarantine audit file written by
        `safeio.write_rejection_audit` — a file in a directory the
        consuming agent's file-reading tools are deny-listed from, which
        already carries the full report bytes. Anywhere an LLM can read
        the result back is a leak, not a diagnostic.
        """
        return self._value

    def _redaction(self) -> str:
        n = len(self._value)
        return f"QuarantineOnlyText(<{n} char{'' if n == 1 else 's'} redacted>)"

    def __bool__(self) -> bool:
        return bool(self._value)

    def __len__(self) -> int:
        return len(self._value)

    def __eq__(self, other: object) -> bool:
        # Same-type only. Comparing against a bare `str` would turn the
        # holder into a payload oracle and would let `==` stand in for an
        # unwrap at a call site that never names the reveal.
        if isinstance(other, QuarantineOnlyText):
            return self._value == other._value
        return NotImplemented

    __hash__ = None  # type: ignore[assignment]


class QuarantineOnly(_OpaqueHolder):
    """Opaque holder for a mapping of untrusted strings.

    Used for `honeypot.HoneypotResult.api_error_details` and
    `intercept.Verdict.honeypot_api_errors`: scenario name -> provider
    API-error detail.
    """

    __slots__ = ("_values",)

    # `Mapping`, not `dict`: a `MappingProxyType` or any other mapping
    # carries the payload just as well, and `__init__` already accepts one.
    _BARE_TYPES = (Mapping,)

    # Key the rendering of a non-mapping lands under. Angle-bracketed so it
    # cannot collide with a scenario name, which is what every real key is,
    # and so it reads as "the library put this here" in an audit record.
    _UNCOERCED_KEY = "<uncoerced>"

    def __init__(self, values: Mapping[str, str] | None = None) -> None:
        # Normalize to `dict[str, str]` on the way in, which is what the
        # annotation has always claimed and what `to_audit()` promises its
        # caller. A mapping adopted verbatim could carry a non-`str` KEY
        # straight through `reveal_for_quarantine_record()` into the audit
        # record, and `json.dumps(..., default=str)` — the exact call the
        # audit writer makes — then raises `TypeError`, because `default` is
        # consulted for values only, never for keys. So the record we are
        # trying to preserve is the thing that fails to be written: a crash
        # in place of a leak, which is not the trade this module makes
        # anywhere else. Values get the same treatment so the record stays
        # serializable with no `default=` hook at all, as `to_audit()`'s
        # contract says and its tests pin.
        #
        # Normalization is per-item and cannot raise; a `str` is kept
        # verbatim so a real diagnostic never picks up `repr()` quotes.
        self._values: dict[str, str] = (
            {self._as_text(k): self._as_text(v) for k, v in values.items()}
            if values
            else {}
        )

    @classmethod
    def _as_text(cls, value: object) -> str:
        """A `str` unchanged; anything else rendered inside the holder."""
        return value if isinstance(value, str) else cls._render_unexpected(value)

    @classmethod
    def _adopt_foreign(cls, value: object) -> QuarantineOnly:
        """Wrap a non-mapping. One expression: no bare local to leak."""
        return cls({cls._UNCOERCED_KEY: cls._render_unexpected(value)})

    @classmethod
    def from_texts(cls, texts: Mapping[str, QuarantineOnlyText]) -> QuarantineOnly:
        """Re-key a set of single-value holders into one mapping holder.

        A transfer between two opaque holders, kept inside this module on
        purpose: the alternative is for the caller to unwrap each
        `QuarantineOnlyText` into a bare `str` local, build a plain dict,
        and re-wrap — which recreates, in the caller, exactly the
        unwrapped window the holders exist to remove. Nothing raw crosses
        the module boundary here; the result is wrapped again before it is
        returned.
        """
        return cls({k: v.reveal_for_quarantine_record() for k, v in texts.items()})

    def reveal_for_quarantine_record(self) -> dict[str, str]:
        """Return the raw mapping. ONE legal destination.

        That destination is the quarantine audit file written by
        `safeio.write_rejection_audit` — a file in a directory the
        consuming agent's file-reading tools are deny-listed from, which
        already carries the full report bytes. Anywhere an LLM can read
        the result back is a leak, not a diagnostic.
        """
        return dict(self._values)

    def _redaction(self) -> str:
        n = len(self._values)
        return f"QuarantineOnly(<{n} entr{'y' if n == 1 else 'ies'} redacted>)"

    def __bool__(self) -> bool:
        return bool(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, QuarantineOnly):
            return self._values == other._values
        return NotImplemented

    __hash__ = None  # type: ignore[assignment]  # mutable payload


class QuarantineFieldsCoerced:
    """Mixin: keep the named fields wrapped, whoever assigns them.

    A holder-typed field is only a promise the CONSTRUCTOR keeps. The
    library keeps it — `honeypot._error_detail` wraps at the point the
    provider bytes are parsed — but the dataclasses still ACCEPTED a bare
    payload from anyone else:

        Verdict(..., honeypot_api_errors={"A": provider_body})
        dataclasses.replace(verdict, honeypot_api_errors={...})
        scenario_result.api_error_detail = provider_body

    Each of those left a plain `str` / `dict` on a public object, and the
    next `repr()`, log line or `json.dumps` spilled it — the exact leak the
    holders exist to stop, reintroduced by a caller who never read this
    module. Containment that depends on every future caller reading the
    annotation is a convention, not a boundary.

    Subclasses declare `_QUARANTINE_FIELDS = {field_name: holder_class}`
    (a plain class attribute, deliberately un-annotated so `@dataclass`
    does not mistake it for a field). Every assignment to one of those
    names is funnelled through `holder.coerce()`.

    `__setattr__` is the single choke point on purpose, because the
    dataclass-generated `__init__` assigns through it too. That covers
    construction, `dataclasses.replace` (which re-invokes `__init__`), and
    post-construction assignment with one mechanism — a `__post_init__`
    would handle only the first two and would need keeping in step with
    this. It is deliberately not a metaclass or a validation framework:
    three fields, one dict lookup per attribute write.

    What it does not cover, and does not claim to: `object.__setattr__`,
    `instance.__dict__[...] = ...`, and unpickling, all of which write the
    instance dict directly. Those are deliberate circumvention, in the same
    class as reading `holder._values` — see the module docstring.
    """

    # field name -> holder class. Overridden per dataclass.
    _QUARANTINE_FIELDS: dict[str, type[_OpaqueHolder]] = {}

    def __setattr__(self, name: str, value: object) -> None:
        holder = self._QUARANTINE_FIELDS.get(name)
        object.__setattr__(self, name, holder.coerce(value) if holder else value)
