"""Generic redaction: the backstop, applied to every view before the model sees it.

The guarantee lives in the projections: views are closed schemas, tabular views keep
only allowlisted columns, and no view carries a display name, given name, phone number
or coordinate. This layer is best effort over what an allowlisted column carries in
free text, a command line or a nested JSON string: secrets by pattern in any string,
secret-bearing and personal fields by name at any depth, and the same inside any string
that is itself a JSON object or array. Emails and user principal names are kept on
purpose; they are the join keys of the investigation.
"""

import json
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
    # Single-letter flags followed by whitespace and a value: mysql -p, sqlcmd -P. A
    # purely numeric value is a port (ssh -p 22), not a password, and is left alone.
    (
        re.compile(r"(?<!\S)(-[pP])(\s+)(?!\d+(?:\s|$))" + _QUOTED_OR_WORD),
        lambda m: f"{m.group(1)}{m.group(2)}[REDACTED:secret]",
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
        "displayname",
        "accountdisplayname",
        "userdisplayname",
        "senderdisplayname",
        "targetaccountdisplayname",
        "fullname",
    }
)
"""Field names, normalised by lowercasing and dropping separators, whose values are
personal data whatever the tool."""

_SECRET_FIELD_SUFFIXES: tuple[str, ...] = (
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "credential",
    "credentials",
    "privatekey",
    "passwordhash",
    "nthash",
    "ntlmhash",
    "lmhash",
)
"""Normalised field-name suffixes whose values are secrets: ``ServiceAccountPwd``,
``client_secret``, ``refreshToken``, ``NtlmHash``. File hashes are not among them."""

_SEPARATORS = re.compile(r"[\s_\-.]")


def _normalise(key: str) -> str:
    return _SEPARATORS.sub("", key).lower()


def is_pii_field(key: str) -> bool:
    return _normalise(key) in _PII_FIELDS


def is_secret_field(key: str) -> bool:
    return _normalise(key).endswith(_SECRET_FIELD_SUFFIXES)


def redact_text(text: str) -> str:
    """Redact a string. A string that is itself a JSON object or array is parsed,
    redacted as a value and re-serialised compactly; anything else is pattern-matched."""
    stripped = text.strip()
    if stripped[:1] in "{[":
        try:
            embedded = json.loads(stripped)
        except ValueError:
            embedded = None
        if isinstance(embedded, dict | list) and embedded:
            return json.dumps(redact(embedded), ensure_ascii=False, separators=(",", ":"))
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
            key: f"[REDACTED:{key}]" if is_pii_field(key) or is_secret_field(key) else redact(item)
            for key, item in value.items()
        }
    return value
