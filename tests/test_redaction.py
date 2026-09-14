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


def test_json_inside_a_string_is_parsed_redacted_and_reserialised():
    inner = (
        '{"ServiceName":"cfgmgmt-agent","ServiceAccountPwd":"S3cret!Svc","user":"jdoe",'
        '"Nested":{"NtlmHash":"aad3b435b51404eeaad3b435b51404ee","AccessToken":"abc"},'
        f'"raw":"Bearer {JWT}"}}'
    )
    out = redact({"AdditionalFields": inner, "list": '[{"phone": "+33 6"}, 1]'})
    parsed = json.loads(out["AdditionalFields"])
    assert parsed["ServiceName"] == "cfgmgmt-agent"
    assert parsed["user"] == "jdoe"
    assert parsed["ServiceAccountPwd"] == "[REDACTED:ServiceAccountPwd]"
    assert parsed["Nested"] == {
        "NtlmHash": "[REDACTED:NtlmHash]",
        "AccessToken": "[REDACTED:AccessToken]",
    }
    assert parsed["raw"] == "Bearer [REDACTED:jwt]"
    assert json.loads(out["list"]) == [{"phone": "[REDACTED:phone]"}, 1]
    for leaked in ("S3cret!Svc", "aad3b435", JWT, "+33 6"):
        assert leaked not in json.dumps(out)


def test_strings_that_are_not_json_objects_are_left_alone():
    for text in ("{not json", "123", '"a string"', "null", "[unclosed", "{}"):
        assert redact(text) == text


def test_secret_bearing_field_names_are_redacted_at_any_depth():
    out = redact(
        {
            "ServiceAccountPwd": "x",
            "client_secret": "y",
            "refreshToken": "z",
            "PasswordHash": "h",
            "SHA256": "3f5a9c1e",
            "FileHash": "abc",
            "tokens_used": 12,
        }
    )
    assert out["ServiceAccountPwd"] == "[REDACTED:ServiceAccountPwd]"
    assert out["client_secret"] == "[REDACTED:client_secret]"
    assert out["refreshToken"] == "[REDACTED:refreshToken]"
    assert out["PasswordHash"] == "[REDACTED:PasswordHash]"
    assert out["SHA256"] == "3f5a9c1e" and out["FileHash"] == "abc"
    assert out["tokens_used"] == 12


def test_single_letter_password_flags_with_a_value():
    assert redact("mysql -u root -p hunter2 -h db") == "mysql -u root -p [REDACTED:secret] -h db"
    assert redact("sqlcmd -S srv -U sa -P 'S3cret!'") == "sqlcmd -S srv -U sa -P [REDACTED:secret]"
    # A numeric value after -p is a port, not a password.
    assert redact("ssh -p 22 host") == "ssh -p 22 host"
    assert redact("psql -p 5432 -U app") == "psql -p 5432 -U app"


def test_display_names_are_dropped_by_field_name():
    out = redact({"AccountDisplayName": "Jane Doe", "displayName": "Jane Doe", "display_name": "J"})
    assert out == {
        "AccountDisplayName": "[REDACTED:AccountDisplayName]",
        "displayName": "[REDACTED:displayName]",
        "display_name": "[REDACTED:display_name]",
    }
