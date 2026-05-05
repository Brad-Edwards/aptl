"""Tests for the shared redaction helper used at serialization boundaries."""

import pytest

from aptl.utils.redaction import REDACTED, redact


class TestRedactScalars:
    def test_replaces_password_value(self):
        assert redact({"password": "hunter2"}) == {"password": REDACTED}

    @pytest.mark.parametrize(
        "key",
        [
            "password",
            "passwd",
            "passphrase",
            "pass",
            "db_pass",
            "secret",
            "token",
            "credential",
            "credentials",
            "authorization",
            "cookie",
            "jwt",
            "bearer",
            "api_key",
            "apikey",
            "key",
            "session",
            "session_id",
        ],
    )
    def test_each_sensitive_token_redacts(self, key):
        assert redact({key: "x"}) == {key: REDACTED}

    @pytest.mark.parametrize(
        "key",
        ["Password", "API_KEY", "Authorization", "JWT", "Cookie", "SECRET"],
    )
    def test_case_insensitive(self, key):
        assert redact({key: "x"}) == {key: REDACTED}

    def test_redacts_credential_value_class(self):
        # Synthetic stand-ins for credential-shaped values. Real lab
        # defaults are not embedded here (those would publish secrets in
        # the source tree).
        out = redact(
            {
                "credentials": "PLACEHOLDER_USER/PLACEHOLDER_PASSWORD",
                "password": "PLACEHOLDER_PASSWORD_VALUE",
                "token": "PLACEHOLDER_JWT_VALUE",
            }
        )
        for value in out.values():
            assert value == REDACTED

    def test_redacts_non_string_values(self):
        # bools, ints, None on sensitive keys are still credential material in
        # some encodings; mark them rather than serializing the raw value.
        out = redact({"password": 12345, "token": None, "secret": True})
        assert out == {"password": REDACTED, "token": REDACTED, "secret": REDACTED}

    def test_preserves_non_sensitive_scalars(self):
        out = redact({"name": "wazuh-manager", "port": 55000, "ok": True})
        assert out == {"name": "wazuh-manager", "port": 55000, "ok": True}


class TestSafeKeyAllowlist:
    @pytest.mark.parametrize(
        "key",
        [
            "key_path",
            "key_file",
            "keypath",
            "keyfile",
            "ssh_key_path",
            "ssh_keyfile",
            "public_key",
            "publickey",
        ],
    )
    def test_path_like_key_names_are_not_redacted(self, key):
        out = redact({key: "~/.ssh/aptl_lab_key"})
        assert out == {key: "~/.ssh/aptl_lab_key"}

    @pytest.mark.parametrize("key", ["ssh_key", "sshkey"])
    def test_bare_ssh_key_is_treated_as_sensitive(self, key):
        # `ssh_key` could be the private-key material itself; only the
        # explicitly path-suffixed forms (`ssh_key_path`, `key_path`) are
        # carved out.
        out = redact({key: "anything"})
        assert out == {key: REDACTED}


class TestRecursion:
    def test_recurses_into_nested_dict(self):
        inp = {"outer": {"password": "p", "host": "h"}}
        out = redact(inp)
        assert out == {"outer": {"password": REDACTED, "host": "h"}}

    def test_recurses_into_list_of_dicts(self):
        inp = {"services": [{"credentials": "c", "name": "n"}]}
        out = redact(inp)
        assert out == {"services": [{"credentials": REDACTED, "name": "n"}]}

    def test_recurses_into_tuple_of_dicts(self):
        inp = {"items": ({"token": "t"},)}
        out = redact(inp)
        # Tuples are normalized to lists during recursion (JSON-compatible).
        assert out == {"items": [{"token": REDACTED}]}

    def test_recurses_into_top_level_list(self):
        inp = [{"password": "p"}, "scalar"]
        out = redact(inp)
        assert out == [{"password": REDACTED}, "scalar"]

    def test_handles_deeply_nested_structures(self):
        inp = {"a": {"b": {"c": [{"secret": "s", "ok": 1}]}}}
        out = redact(inp)
        assert out == {"a": {"b": {"c": [{"secret": REDACTED, "ok": 1}]}}}


class TestImmutability:
    def test_does_not_mutate_input_dict(self):
        inp = {"password": "p", "nested": {"token": "t"}}
        snapshot = {"password": "p", "nested": {"token": "t"}}
        redact(inp)
        assert inp == snapshot

    def test_does_not_mutate_input_list(self):
        inp = [{"password": "p"}]
        snapshot = [{"password": "p"}]
        redact(inp)
        assert inp == snapshot


class TestEdgeCases:
    def test_empty_dict_returns_empty_dict(self):
        assert redact({}) == {}

    def test_empty_list_returns_empty_list(self):
        assert redact([]) == []

    def test_top_level_scalar_returned_unchanged(self):
        assert redact("hello") == "hello"
        assert redact(42) == 42
        assert redact(None) is None

    def test_substring_match_in_compound_key(self):
        # Real-world: keys like `ssl_authorization_header` or `oauth_token_url`
        # legitimately should be redacted because they carry credential material.
        out = redact(
            {
                "ssl_authorization_header": "Bearer xyz",
                "oauth_token_url": "https://example.com/token",
                "user_password_hash": "bcrypt$...",
            }
        )
        assert out == {
            "ssl_authorization_header": REDACTED,
            "oauth_token_url": REDACTED,
            "user_password_hash": REDACTED,
        }


class TestStringContentTraversal:
    def test_parses_json_string_value_and_redacts_inner(self):
        out = redact({"body": '{"password":"hunter2","host":"h"}'})
        assert "hunter2" not in out["body"]
        assert REDACTED in out["body"]
        assert '"host":"h"' in out["body"]

    def test_handles_mcp_content_text_envelope(self):
        # Real MCP shape: {content: [{type:'text', text: JSON.stringify(data)}]}
        out = redact(
            {"content": [{"type": "text", "text": '{"data":{"api_key":"abc","ok":true}}'}]}
        )
        text = out["content"][0]["text"]
        assert "abc" not in text
        assert REDACTED in text
        assert '"ok":true' in text

    def test_leaves_non_json_strings_unchanged(self):
        assert redact({"msg": "hello world"}) == {"msg": "hello world"}
        assert redact({"msg": "not really {json"}) == {"msg": "not really {json"}

    @pytest.mark.parametrize(
        "input_str,expected",
        [
            ("Authorization: Bearer abc.def.ghi", "Authorization: Bearer [REDACTED]"),
            ("authorization: Basic dXNlcjpwYXNz", "authorization: Basic [REDACTED]"),
            ("Bearer raw-token-value", "Bearer [REDACTED]"),
            ("--password=hunter2", "--password=[REDACTED]"),
            ("password: hunter2", "password: [REDACTED]"),
            ("api_key=abc123", "api_key=[REDACTED]"),
            ("token=ey.signed.jwt", "token=[REDACTED]"),
            ("--password hunter2", "--password [REDACTED]"),
            ("--token abc123", "--token [REDACTED]"),
        ],
    )
    def test_inline_secret_patterns(self, input_str, expected):
        out = redact({"command": input_str})
        assert out["command"] == expected

    def test_curl_command_with_authorization_header(self):
        out = redact(
            {"command": "curl -H 'Authorization: Bearer abc' https://example.com"}
        )
        assert "abc" not in out["command"]
        assert REDACTED in out["command"]

    def test_url_query_string_with_sensitive_params(self):
        out = redact({"url": "https://api.example.com?api_key=secret123&user=alice"})
        assert "secret123" not in out["url"]
        assert "user=alice" in out["url"]

    def test_preserves_closing_quote_around_authorization_header(self):
        # `\S+` would consume the trailing `'`; the bounded value pattern
        # must stop at quote characters so the closing `'` stays in the
        # output and downstream diagnostic structure is preserved.
        out = redact(
            {"command": "curl -H 'Authorization: Bearer abc.def' https://x"}
        )
        assert "abc.def" not in out["command"]
        # Authorization scheme labelled, value masked, surrounding quotes intact.
        assert "Bearer [REDACTED]" in out["command"]
        assert "'Authorization: Bearer [REDACTED]'" in out["command"]
        assert out["command"].endswith("https://x")

    def test_redacts_cookie_header(self):
        out = redact({"command": "curl -H 'Cookie: session=xyz' https://x"})
        assert "session=xyz" not in out["command"]
        assert "[REDACTED]" in out["command"]

    def test_redacts_url_userinfo_password(self):
        out = redact({"url": "https://alice:hunter2@host.example.com/path"})
        # password masked, user kept for diagnostics, host preserved
        assert "hunter2" not in out["url"]
        assert "alice" in out["url"]
        assert "host.example.com/path" in out["url"]
        assert "[REDACTED]" in out["url"]

    def test_redacts_pem_private_key_block(self):
        pem = (
            "before\n"
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n"
            "secretkeymaterial...\n"
            "-----END PRIVATE KEY-----\n"
            "after"
        )
        out = redact({"blob": pem})
        assert "MIIEvQIBADANBg" not in out["blob"]
        assert "secretkeymaterial" not in out["blob"]
        # Markers preserved so the reader knows what was masked.
        assert "-----BEGIN PRIVATE KEY-----" in out["blob"]
        assert "-----END PRIVATE KEY-----" in out["blob"]
        assert "before" in out["blob"]
        assert "after" in out["blob"]

    def test_redacts_pem_rsa_private_key_block(self):
        pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "secretmaterial\n"
            "-----END RSA PRIVATE KEY-----"
        )
        out = redact({"blob": pem})
        assert "secretmaterial" not in out["blob"]
        assert "-----BEGIN RSA PRIVATE KEY-----" in out["blob"]
        assert "-----END RSA PRIVATE KEY-----" in out["blob"]


class TestArrayPairCliFlags:
    def test_pair_form_cli_flag_redacts_following_value(self):
        # ["--password", "hunter2"] should mask the positional value.
        out = redact(["--password", "hunter2", "--verbose"])
        assert out == ["--password", REDACTED, "--verbose"]

    def test_multiple_pair_form_flags(self):
        out = redact(["--password", "p1", "--token", "t2", "--ok"])
        assert out == ["--password", REDACTED, "--token", REDACTED, "--ok"]

    def test_non_sensitive_flag_value_left_alone(self):
        out = redact(["--verbose", "true", "--retries", "3"])
        assert out == ["--verbose", "true", "--retries", "3"]

    def test_pair_detection_respects_sensitive_flag_only(self):
        # `--port 22` is not sensitive; value preserved.
        out = redact(["--port", "22", "--password", "x"])
        assert out == ["--port", "22", "--password", REDACTED]
