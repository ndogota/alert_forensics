"""Generic redaction: the second layer, applied to every view before the model sees it.

The first layer is each tool's projection, which drops what the model has no use for.
This layer catches what a projection passes through: secrets by pattern in any string,
personal data by field name at any depth. Emails and user principal names are kept on
purpose; they are the join keys of the investigation.
"""

import re
from collections.abc import Callable

from pydantic import JsonValue

_QUOTED_OR_WORD = r"""("[^"]*"|'[^']*'|\S+)"""

_SECRET_PATTERNS: list[tuple[re.Pattern[str], str | Callable[[re.Match[str]], str]]] = [
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
        "[REDACTED:private_key]",
    ),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        "[REDACTED:jwt]",
    ),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}"), "Bearer [REDACTED:token]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED:aws_key]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"), "[REDACTED:token]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED:token]"),
    # key=value and key: value, where the key names a secret.
    (
        re.compile(
            r"(?i)\b(password|passwd|pwd|passphrase|secret|token|api[_-]?key|client[_-]?secret)"
            r"(\s*[:=]\s*)" + _QUOTED_OR_WORD
        ),
        lambda m: f"{m.group(1)}=[REDACTED:secret]",
    ),
    # Command-line switches: -Password x, --password=x, /password:x, /password=x.
    (
        re.compile(
            r"(?i)(?<!\w)((?:-{1,2}|/)(?:password|passwd|pwd|passphrase|secret|token|api[_-]?key))"
            r"([\s:=]+)" + _QUOTED_OR_WORD
        ),
        lambda m: f"{m.group(1)}{m.group(2)}[REDACTED:secret]",
    ),
    (
        re.compile(r"(?i)\b(ConvertTo-SecureString)\s+" + _QUOTED_OR_WORD),
        lambda m: f"{m.group(1)} [REDACTED:secret]",
    ),
]

_PII_FIELDS: frozenset[str] = frozenset(
    {
        "phone",
        "phone2",
        "mobile",
        "telephone",
        "first",
        "last",
        "firstname",
        "lastname",
        "givenname",
        "surname",
        "familyname",
        "middlename",
        "dateofbirth",
        "dob",
        "birthdate",
        "ssn",
        "nationalid",
        "passport",
        "taxid",
        "iban",
        "homeaddress",
        "streetaddress",
        "street",
        "lat",
        "long",
        "latitude",
        "longitude",
        "worklat",
        "worklong",
        "salary",
    }
)
"""Field names, normalised by lowercasing and dropping separators, whose values are
personal data whatever the tool."""

_SEPARATORS = re.compile(r"[\s_\-.]")


def _normalise(key: str) -> str:
    return _SEPARATORS.sub("", key).lower()


def is_pii_field(key: str) -> bool:
    return _normalise(key) in _PII_FIELDS


def redact_text(text: str) -> str:
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact(value: JsonValue) -> JsonValue:
    """Return a redacted copy of a JSON value. The input is never mutated."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, dict):
        return {
            key: f"[REDACTED:{key}]" if is_pii_field(key) else redact(item)
            for key, item in value.items()
        }
    return value
