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
    """Shared redaction machinery. Subclasses supply `_redaction()` only.

    Factored out so the two holders cannot drift: a `__repr__` that
    forgets to redact is the whole failure mode this module exists to
    prevent, and duplicating it twice is how that happens.
    """

    __slots__ = ()

    def _redaction(self) -> str:  # pragma: no cover - overridden
        raise NotImplementedError

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

    def __init__(self, value: str = "") -> None:
        self._value: str = value

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

    def __init__(self, values: Mapping[str, str] | None = None) -> None:
        self._values: dict[str, str] = dict(values) if values else {}

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
