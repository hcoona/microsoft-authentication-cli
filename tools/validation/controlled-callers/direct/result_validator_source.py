"""INERT proposal: memory-only protocol 1 validation for the direct WSL caller.

No input loader, launcher, file writer, token decoder, or resource client is present.
The eventual caller must catch every exception without rendering exception text.
This module has not been executed or accepted for experiment use.
"""

SOURCE_ADMITTED = False
if not SOURCE_ADMITTED:
    raise SystemExit("INERT: independent source and exact-call admission required")

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re


FAILURES = frozenset((
    "invalid_request", "interaction_required", "account_ambiguous",
    "identity_validation_failed", "cancelled", "denied",
    "mechanism_unavailable", "temporarily_unavailable", "timeout",
    "internal_failure",
))
SUCCESS_FIELDS = frozenset((
    "accessToken", "tokenType", "expiresOn", "accountEmail", "tenantId",
    "authority", "scopes", "mechanism", "interaction", "warnings",
))
FAILURE_FORBIDDEN = SUCCESS_FIELDS | frozenset((
    "correlationId", "refreshToken", "idToken", "authorizationCode", "claims",
))
GUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
INSTANT = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.(?P<fraction>\d{1,7}))?"
    r"(?:Z|[+-]\d{2}:\d{2})\Z", re.ASCII)


@dataclass(frozen=True, repr=False)
class Expected:
    # The initial direct route admits ASCII arguments only. Do not substitute
    # casefold() for .NET OrdinalIgnoreCase on arbitrary Unicode selectors.
    email: str
    tenant: str | None
    scopes: tuple[str, ...]
    interaction_allowed: bool
    outcome: str
    required_interaction: str | None = None


class InvalidFrame(Exception):
    """No private input, arbitrary reason, or parser diagnostic in the exception."""


def require(condition):
    if not condition:
        raise InvalidFrame()


def object_pairs(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def reject_constant(_):
    raise InvalidFrame()


def precheck_nesting(text):
    # Bound parser recursion without inspecting or retaining unknown field values.
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            require(depth <= 32)
        elif char in "]}":
            depth -= 1
            require(depth >= 0)
    require(depth == 0 and not quoted)


def direct_token(value):
    # Deliberate initial caller subset, not the product request grammar.
    return type(value) is str and bool(value) and all(33 <= ord(c) <= 126 and ord(c) not in (34, 39) for c in value)


def valid_expected(expected):
    # The eventual caller MUST run this before product launch, independently of
    # the defensive repetition in validate_complete. URI resources are unsupported
    # by this initial caller; do not broaden this into a .NET URI approximation.
    require(type(expected) is Expected)
    require(direct_token(expected.email))
    require(3 <= len(expected.email) <= 320)
    require(re.fullmatch(r"[^\s@]+@[^\s@]+", expected.email) is not None)
    require(expected.tenant is None or
            (type(expected.tenant) is str and GUID.fullmatch(expected.tenant)))
    require(type(expected.scopes) is tuple and 1 <= len(expected.scopes) <= 64)
    require(all(direct_token(item) and 1 <= len(item) <= 2048
                and re.fullmatch(r"\S+/[^\s/]+", item) for item in expected.scopes))
    require(all(GUID.fullmatch(item.rsplit("/", 1)[0]) for item in expected.scopes))
    require(len(set(expected.scopes)) == len(expected.scopes))
    require(len({item.rsplit("/", 1)[0] for item in expected.scopes}) == 1)
    require(not any(item.endswith("/.default") for item in expected.scopes)
            or len(expected.scopes) == 1)
    require(type(expected.interaction_allowed) is bool)
    require(expected.outcome == "success" or expected.outcome in FAILURES)
    require(expected.required_interaction in (None, "silent", "interactive"))
    require(expected.required_interaction != "interactive" or expected.interaction_allowed)


def validate_complete(stdout, stderr, exit_code, both_eof, expected, received_at):
    """Return fixed safe fields only; never return parsed private values.

    Transport/native-lifetime evidence remains the caller's separate obligation.
    An exit code or this result cannot establish native Windows termination, UI
    absence, exact SDK call counts, or internal /.default operation association.
    Caller supplies a UTC receipt time; no token decoding or minimum lifetime.
    """
    try:
        valid_expected(expected)
        require(type(received_at) is datetime and received_at.tzinfo is not None)
        require(received_at.utcoffset() == timezone.utc.utcoffset(received_at))
        require(type(stdout) in (bytes, bytearray) and 0 < len(stdout) <= 1048576)
        require(type(stderr) in (bytes, bytearray) and len(stderr) <= 8192)
        require(both_eof is True and type(exit_code) is int and exit_code in (0, 1))
        # Telemetry is explicitly off in the planned caller's command.
        require(not stderr and stdout.endswith(b"\n") and stdout.count(b"\n") == 1)
        require(not stdout.startswith(b"\xef\xbb\xbf") and b"\r" not in stdout)
        text = stdout[:-1].decode("utf-8", errors="strict")
        precheck_nesting(text)
        result = json.loads(text, object_pairs_hook=object_pairs,
                            parse_constant=reject_constant)
        require(type(result) is dict)
        require(type(result.get("protocol")) is int and result["protocol"] == 1)
        outcome = result.get("outcome")
        require(type(outcome) is str and outcome == expected.outcome)
        if outcome != "success":
            require(exit_code == 1 and outcome in FAILURES)
            require(not (FAILURE_FORBIDDEN & result.keys()))
            reason = result.get("reason")
            require(type(reason) is str and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", reason))
            # Valid unknown reasons and all additive values are discarded.
            return {"protocolValid": True, "outcome": outcome,
                    "expectationMatched": True, "successMetadataValidated": False,
                    "apiRoute": None, "persistenceUnconfirmed": False}

        require(exit_code == 0 and SUCCESS_FIELDS <= result.keys())
        require(all(type(result[name]) is str and result[name]
                    for name in ("accessToken", "tokenType", "accountEmail", "tenantId",
                                 "authority", "expiresOn", "mechanism", "interaction")))
        require(result["accountEmail"].isascii()
                and result["accountEmail"].lower() == expected.email.lower())
        tenant = result["tenantId"]
        require(GUID.fullmatch(tenant) is not None)
        require(expected.tenant is None or tenant.lower() == expected.tenant.lower())
        require(result["authority"] == "https://login.microsoftonline.com/" + tenant.lower())
        expiry = result["expiresOn"]
        match = INSTANT.fullmatch(expiry)
        require(match is not None)
        expiry_microseconds = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
        fraction = match.group("fraction") or ""
        final_tick = int(fraction[6]) if len(fraction) == 7 else 0
        # Preserve .NET's seventh fractional digit against the supplied receipt
        # time rather than accidentally imposing a one-microsecond lifetime.
        require(expiry_microseconds > received_at or
                (expiry_microseconds == received_at and final_tick > 0))
        grants = result["scopes"]
        require(type(grants) is list and all(type(item) is str and item for item in grants))
        is_default = len(expected.scopes) == 1 and expected.scopes[0].endswith("/.default")
        require(is_default or all(item in grants for item in expected.scopes))
        require(result["mechanism"] == "wam")
        route = result["interaction"]
        require(route in ("silent", "interactive"))
        require(expected.interaction_allowed or route == "silent")
        require(expected.required_interaction is None or route == expected.required_interaction)
        warnings = result["warnings"]
        require(type(warnings) is list and all(type(item) is str for item in warnings))
        require(len(warnings) == len(set(warnings)))
        require(set(warnings) <= {"persistence_unconfirmed", "persistence_failed"})
        require("persistence_unconfirmed" in warnings)
        if "correlationId" in result:
            require(type(result["correlationId"]) is str and GUID.fullmatch(result["correlationId"]))
        return {"protocolValid": True, "outcome": "success", "expectationMatched": True,
                "successMetadataValidated": True, "apiRoute": route,
                "persistenceUnconfirmed": True}
    except (Exception, RecursionError):
        # Do not return str(error), exception class names, raw JSON, unknown fields,
        # private selectors, token lengths/hashes, or parser position/context.
        return {"protocolValid": False, "outcome": None, "expectationMatched": False,
                "successMetadataValidated": False, "apiRoute": None,
                "persistenceUnconfirmed": False}
