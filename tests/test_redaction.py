import copy
import json

from alert_forensics.tools import redact

JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def test_secrets_are_redacted_by_pattern_inside_any_string():
    value = {
        "jwt": f"token is {JWT} ok",
        "bearer": "Authorization: Bearer abcDEF0123456789abcDEF0123456789",
        "aws": "found AKIAIOSFODNN7EXAMPLE in the script",
        "github": "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
        "kv": "api_key=sk-live-1234567890 client_secret: 'zzz'",
        "cmd": "RemoteSupport.ClientSetup.exe /silent /password=Hunter2! /relay=relay.example.net",
        "ps": "powershell -Command ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force",
        "switch": "net use \\\\srv\\share -Password 'Hunter2!' /user:CONTOSO\\svc",
    }
    out = redact(value)
    text = json.dumps(out)
    for secret in (
        JWT,
        "abcDEF0123456789abcDEF0123456789",
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "MIIEow",
        "sk-live-1234567890",
        "zzz",
        "Hunter2!",
        "P@ssw0rd",
    ):
        assert secret not in text, secret
    assert out["jwt"] == "token is [REDACTED:jwt] ok"
    assert out["bearer"] == "Authorization: Bearer [REDACTED:token]"
    assert out["cmd"] == (
        "RemoteSupport.ClientSetup.exe /silent /password=[REDACTED:secret] /relay=relay.example.net"
    )
    assert "[REDACTED:private_key]" in out["pem"]
    assert "[REDACTED:secret]" in out["kv"] and "api_key=" in out["kv"]
    assert "/user:CONTOSO\\svc" in out["switch"]


def test_personal_data_is_redacted_by_field_name_and_join_keys_are_kept():
    value = {
        "email": "jdoe@contoso.com",
        "userPrincipalName": "jdoe@contoso.com",
        "AccountName": "jdoe",
        "first": "Jane",
        "last_name": "Doe",
        "phone": "+33 6 12 34 56 78",
        "work_lat": "48.8566",
        "Date-Of-Birth": "1990-01-01",
        "nested": [{"Phone2": "x"}, {"iban": "FR76 3000 6000 0112 3456 7890 189"}],
        "last_analysis_date": 1789300000,
    }
    out = redact(value)
    assert out["email"] == "jdoe@contoso.com"
    assert out["userPrincipalName"] == "jdoe@contoso.com"
    assert out["AccountName"] == "jdoe"
    assert out["first"] == "[REDACTED:first]"
    assert out["last_name"] == "[REDACTED:last_name]"
    assert out["phone"] == "[REDACTED:phone]"
    assert out["work_lat"] == "[REDACTED:work_lat]"
    assert out["Date-Of-Birth"] == "[REDACTED:Date-Of-Birth]"
    assert out["nested"] == [{"Phone2": "[REDACTED:Phone2]"}, {"iban": "[REDACTED:iban]"}]
    assert out["last_analysis_date"] == 1789300000


def test_redaction_never_mutates_its_input_and_is_idempotent():
    value = {"a": [f"Bearer {JWT}", {"phone": "1"}], "n": 1, "f": 2.5, "z": None, "b": True}
    before = copy.deepcopy(value)
    once = redact(value)
    assert value == before
    assert redact(once) == once
    assert once["n"] == 1 and once["f"] == 2.5 and once["z"] is None and once["b"] is True


def test_prose_is_left_alone():
    prose = "The token was issued by the identity provider; the password policy requires 14 chars."
    assert redact(prose) == prose
    assert redact("ssh -p 22 host") == "ssh -p 22 host"
    assert redact(["a", 1, None]) == ["a", 1, None]
