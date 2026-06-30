"""Tests for the shared redaction helper used at serialization boundaries."""

import json

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
        # Anchor on the labelled replacement form so a regression that
        # silently dropped the "Bearer" scheme (or the 'abc' value via an
        # unrelated code path) wouldn't be missed.
        out = redact(
            {"command": "curl -H 'Authorization: Bearer abc' https://example.com"}
        )
        assert (
            out["command"]
            == "curl -H 'Authorization: Bearer [REDACTED]' https://example.com"
        )

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
        assert out["command"] == "curl -H 'Cookie: [REDACTED]' https://x"

    def test_redacts_multi_segment_cookie_header(self):
        # `;`-delimited cookie segments must all be masked, not just the
        # first one — a Cookie header is one credential blob.
        out = redact(
            {"command": "curl -H 'Cookie: lang=en; connect.sid=SECRET_VALUE' https://x"}
        )
        assert "lang=en" not in out["command"]
        assert "SECRET_VALUE" not in out["command"]
        assert "Cookie: [REDACTED]" in out["command"]

    def test_redacts_set_cookie_response_header(self):
        out = redact({"text": "Set-Cookie: sessionId=abc.def; Path=/; HttpOnly"})
        assert "sessionId=abc.def" not in out["text"]
        assert "Set-Cookie: [REDACTED]" in out["text"]

    @pytest.mark.parametrize(
        "input_str,leak_token",
        [
            ("access_token=SECRET_AT", "SECRET_AT"),
            ("refresh_token=SECRET_RT", "SECRET_RT"),
            ("client_secret=SECRET_CS", "SECRET_CS"),
            ("db_password=SECRET_DB", "SECRET_DB"),
            ("--client-secret SECRET_CLI", "SECRET_CLI"),
            ("--access-token SECRET_AT2", "SECRET_AT2"),
        ],
    )
    def test_redacts_compound_credential_names(self, input_str, leak_token):
        # `_` and `-` must not block matching — `\b<key>\b` boundaries
        # would fail because `_` is a word character.
        out = redact({"command": input_str})
        assert leak_token not in out["command"]
        assert REDACTED in out["command"]

    def test_redacts_url_userinfo_password(self):
        # Anchor on the exact replacement form so a regression that
        # mangled the userinfo structure would be caught.
        out = redact({"url": "https://alice:hunter2@host.example.com/path"})
        assert out["url"] == "https://alice:[REDACTED]@host.example.com/path"

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


class TestCommandFlagRedaction:
    """Command-line credential forms mirrored from redaction.ts (#281).

    Synthetic credential stand-ins only — no real lab secrets in the
    source tree (same convention as the rest of this module).
    """

    # ---- short -p password flag (hydra family) ----

    def test_short_p_password_non_numeric(self):
        out = redact("hydra -l u -p hunter2 host ssh")
        assert "hunter2" not in out
        assert "-p [REDACTED]" in out

    def test_short_p_numeric_redacted_when_credential_tool_present(self):
        # A numeric -p next to a credential tool is a password, not a port.
        assert "123456" not in redact("hydra -l u -p 123456 host ssh")
        assert "1234" not in redact("sshpass -p 1234 ssh user@host")

    def test_short_p_numeric_kept_for_nmap(self):
        assert "-p 22" in redact("nmap -p 22 10.0.0.1")
        assert "-p 22,80,443" in redact("nmap -p 22,80,443 host")
        assert "-p 1-1024" in redact("nmap -p 1-1024 target")

    def test_short_p_through_wrapper_pipelines(self):
        assert "hunter2" not in redact("proxychains4 hydra -l u -p hunter2 host ssh")
        assert "hunter2" not in redact("sudo hydra -p hunter2 host ssh")

    def test_short_p_equals_and_attached_forms(self):
        assert "hunter2" not in redact("hydra -l u -p=hunter2 host ssh")
        assert "hunter2" not in redact("hydra -l u -phunter2 host ssh")

    def test_short_p_quoted_multiword_value(self):
        assert "secret" not in redact('hydra -p "secret phrase" host ssh')

    def test_short_p_escape_aware_value(self):
        out = redact("hydra -l u -p correct\\ horse host ssh")
        assert "correct" not in out
        assert "horse" not in out

    def test_short_p_per_segment_keeps_port_in_other_segment(self):
        out = redact("nmap -p 22 10.0.0.1 && hydra -l u -p hunter2 10.0.0.1 ssh")
        assert "-p 22" in out
        assert "hunter2" not in out
        assert "-p [REDACTED]" in out

    def test_short_p_per_segment_respects_pipe(self):
        out = redact("nmap -p 80 host | grep open ; hydra -p hunter2 h ssh")
        assert "-p 80" in out
        assert "hunter2" not in out

    def test_short_p_numeric_redacted_for_evil_winrm_and_bloodhound(self):
        assert "12345" not in redact("evil-winrm -i 10.0.0.1 -u alice -p 12345")
        assert "12345" not in redact(
            "bloodhound-python -u alice -p 12345 -d corp.example -c All"
        )

    # ---- --user / -u / -U Basic-auth & Samba ----

    def test_basic_auth_user_colon_password(self):
        out = redact("curl --user alice:hunter2 https://target/")
        assert "hunter2" not in out
        assert "--user [REDACTED]" in out

    def test_basic_auth_short_u(self):
        assert "hunter2" not in redact("curl -u alice:hunter2 https://target/")

    def test_basic_auth_equals_form(self):
        assert "hunter2" not in redact("curl --user=alice:hunter2 https://target/")

    def test_basic_auth_bare_username_left_alone(self):
        assert "--user alice" in redact("ssh --user alice host")

    def test_basic_auth_url_target_not_redacted(self):
        out = redact("sqlmap -u https://target.example/login --batch")
        assert "https://target.example/login" in out

    def test_basic_auth_url_with_port_not_redacted(self):
        out = redact("gobuster dir -u https://target.example:8443/admin -w words.txt")
        assert "https://target.example:8443/admin" in out

    def test_samba_percent_password_in_capital_u(self):
        assert "hunter2" not in redact("smbclient -U alice%hunter2 //host/share")

    def test_basic_auth_attached_forms(self):
        assert "hunter2" not in redact("curl -ualice:hunter2 https://target.example/")
        assert "hunter2" not in redact("smbclient -Ualice%hunter2 //host/share")

    # ---- -H NTLM hash flag (crackmapexec / nxc / impacket) ----

    def test_ntlm_hash_redacted_for_crackmapexec(self):
        out = redact(
            "crackmapexec smb dc.example -u alice "
            "-H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
        )
        assert "aad3b435" not in out
        assert "8846f7ea" not in out

    def test_ntlm_hash_redacted_for_nxc_attached(self):
        out = redact("nxc smb dc.example -u alice -Haad3b435b51404ee:8846f7eaee")
        assert "aad3b435" not in out
        assert "8846f7ea" not in out

    def test_curl_dash_h_header_not_treated_as_hash(self):
        out = redact("curl -H 'X-Foo: bar' https://target/")
        assert "X-Foo: bar" in out

    # ---- -w LDAP simple-bind password ----

    def test_ldap_w_password_redacted(self):
        out = redact("ldapsearch -x -D cn=admin,dc=lab -w hunter2 -b dc=lab")
        assert "hunter2" not in out

    def test_ldap_w_password_attached_form(self):
        assert "hunter2" not in redact("ldapsearch -x -D cn=admin,dc=lab -whunter2")

    def test_dash_w_wordlist_not_treated_as_ldap_password(self):
        # hydra is not an LDAP tool, so its -w (wait time / wordlist) stays.
        out = redact("hydra -l u -p x -w 5 host ssh")
        assert "-w 5" in out
        assert "-p [REDACTED]" in out

    # ---- quoted standalone option-token normalization ----

    def test_quoted_option_token_normalized_before_flag_matching(self):
        assert "hunter2" not in redact("hydra '-p' hunter2 host ssh")
        assert "hunter2" not in redact('curl "-u" alice:hunter2 https://target/')

    # ---- impacket positional user:password@host ----

    def test_impacket_positional_redacted(self):
        out = redact("psexec.py corp/alice:hunter2@dc.example")
        assert "hunter2" not in out
        assert "alice" in out
        assert "dc.example" in out
        assert "psexec.py" in out

    def test_impacket_positional_redacted_secretsdump(self):
        assert "hunter2" not in redact("secretsdump.py alice:hunter2@dc.example")

    def test_impacket_positional_quoted_password_with_specials(self):
        out_dq = redact('psexec.py corp/alice:"P@ss:w0rd"@dc.example')
        assert "P@ss" not in out_dq
        assert "corp/alice" in out_dq
        assert "@dc.example" in out_dq
        out_sq = redact("psexec.py corp/alice:'P@ss w0rd'@dc.example")
        assert "P@ss" not in out_sq

    def test_non_impacket_user_pair_at_host_left_alone(self):
        out = redact("rsync user:pw@host /local/path")
        assert "user:pw@host" in out

    # ---- composes through top-level redact() on nested structures ----

    def test_command_in_dict_value_is_redacted(self):
        out = redact({"command": "hydra -l admin -p hunter2 10.0.0.1 ssh", "rc": 0})
        assert "hunter2" not in out["command"]
        assert out["rc"] == 0

    def test_command_in_list_is_redacted(self):
        out = redact(["curl --user alice:hunter2 https://target/", "ok"])
        assert "hunter2" not in out[0]

    # ---- idempotency: running redact twice == once ----

    @pytest.mark.parametrize(
        "command",
        [
            "hydra -l u -p hunter2 host ssh",
            "nmap -p 22 10.0.0.1 && hydra -p hunter2 h ssh",
            "crackmapexec smb dc -u alice -H aad3b435:8846f7ea",
            "psexec.py corp/alice:hunter2@dc.example",
            "curl --user alice:hunter2 https://target/",
            "ldapsearch -x -D cn=admin,dc=lab -w hunter2",
            "nmap -p 22,80,443 host",
        ],
    )
    def test_redact_is_idempotent_on_commands(self, command):
        once = redact(command)
        twice = redact(once)
        assert once == twice

    def test_port_only_string_unchanged(self):
        # A bare port spec with no tool context is left intact.
        assert redact("-p 22") == "-p 22"
        assert redact({"args": ["-p", "443"]}) == {"args": ["-p", "443"]}


class TestCommandFlagRedactionOffsetSafety:
    """Regression tests pinning the per-segment offset-recompute fix
    (codex review cycle 1, finding 2). The earlier implementation
    computed segment offsets once and ran six sequential ``.sub()``
    calls on a mutating string; once a quoted credential of length ≠
    [REDACTED] was replaced, later offsets shifted into the wrong
    segment and could over-redact a port spec, a wordlist value, or a
    non-credential userinfo pair."""

    def test_long_quoted_hydra_password_does_not_mask_later_nmap_port(self):
        # The quoted password is much longer than [REDACTED] so the
        # post-DQUOTE-sub offsets shift left by ~25 chars; without the
        # per-pass segment recompute, the later `-p 22` falls back into
        # the hydra segment and gets masked.
        cmd = (
            'hydra -p "ABCDEFGHIJKLMNOPQRSTUVWXYZ" foo && nmap -p 22 10.0.0.1'
        )
        out = redact(cmd)
        assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ" not in out
        assert "-p [REDACTED]" in out
        assert "-p 22" in out  # nmap's port survived

    def test_long_quoted_ldap_password_does_not_mask_later_hydra_w(self):
        # ldapsearch -w <long-pwd> ... && hydra -w 5 ... — `-w 5` is a
        # wait/wordlist for hydra (not an LDAP password); offset drift
        # would mis-classify it as still being in the ldap segment.
        cmd = (
            'ldapsearch -x -D cn=admin,dc=lab -w "ABCDEFGHIJKLMNOPQRSTUVWXYZ" '
            "&& hydra -l u -p x -w 5 host ssh"
        )
        out = redact(cmd)
        assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ" not in out
        assert "-w 5" in out  # hydra wait stays visible

    def test_long_quoted_impacket_password_does_not_mask_later_userinfo(self):
        cmd = (
            'psexec.py corp/alice:"ABCDEFGHIJKLMNOPQRSTUVWXYZ"@dc.example '
            "&& echo unrelated:token@host"
        )
        out = redact(cmd)
        assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ" not in out
        assert "unrelated:token@host" in out


class TestRedactStringScalarBoundary:
    """``redact("...")`` returns a redacted string. Used by the
    runstore boundary's JSON ``default`` hook so non-JSON values
    can't smuggle secrets past the redactor (ADR-029)."""

    def test_redact_of_inline_secret_string(self):
        assert redact("Authorization: Bearer abc.def") == "Authorization: Bearer [REDACTED]"
        assert redact("password: hunter2") == "password: [REDACTED]"

    def test_redact_of_non_secret_string(self):
        assert redact("hello world") == "hello world"


class TestQuoteStripScopedToCredentialSegments:
    """Codex review cycle 2 finding 1: the quoted-option strip used to
    run globally and corrupted non-option text (``echo '-p' hunter2``
    became ``echo -p hunter2`` and then the trailing word was masked as
    if it were a password). The strip is now scoped to segments that
    name a credential-bearing tool."""

    def test_echo_quoted_option_data_is_preserved(self):
        # `echo` is not a credential tool; the quoted `-p` is data, not
        # an argv flag, and the trailing word is just text. Both should
        # survive untouched.
        out = redact("echo '-p' hunter2 file.txt")
        assert out == "echo '-p' hunter2 file.txt"

    def test_grep_quoted_option_data_is_preserved(self):
        out = redact("grep '-u' alice:other file.log")
        # grep is not a credential tool — `-u` here is data, not an auth flag.
        assert out == "grep '-u' alice:other file.log"

    def test_hydra_quoted_option_still_unquotes_and_redacts(self):
        # Parity with the cycle-12 security fix: hydra IS a credential
        # tool, so its segment unquotes and the per-flag matcher fires.
        out = redact("hydra '-p' hunter2 host ssh")
        assert "hunter2" not in out

    def test_curl_quoted_short_u_still_unquotes_and_redacts(self):
        out = redact('curl "-u" alice:hunter2 https://target/')
        assert "hunter2" not in out

    def test_mixed_segments_only_unquote_credential_one(self):
        # Two segments separated by `;`: echo (data) | hydra (credential).
        out = redact("echo '-p' notapwd ; hydra '-p' realpwd host ssh")
        assert "'-p' notapwd" in out  # echo segment preserved
        assert "realpwd" not in out  # hydra segment redacted


class TestBasicAuthShortFlagToolScope:
    """Codex review cycle 2 finding 2: the short ``-u``/``-U`` redactor
    used to fire on any value containing ``:`` or ``%``, regardless of
    the tool. ``date -u +%Y:%m`` (where ``-u`` is the UTC flag and
    ``+%Y:%m`` is just an unrelated value) was misread as Basic auth.
    Short ``-u``/``-U`` are now scoped to tool families that actually
    use those flags for auth; long ``--user`` stays content-based."""

    def test_date_short_u_format_string_preserved(self):
        out = redact("date -u +%Y:%m:%d")
        assert "+%Y:%m:%d" in out

    def test_grep_short_u_with_colon_value_preserved(self):
        # `grep -u something:other file` — grep doesn't use -u for auth.
        out = redact("grep -u alice:other file.log")
        assert "alice:other" in out

    def test_curl_short_u_credential_still_redacted(self):
        # curl is in the basic-auth-short tools list — content-based
        # check still applies and the credential is masked.
        assert "hunter2" not in redact("curl -u alice:hunter2 https://target/")

    def test_long_user_stays_content_based_even_for_unknown_tool(self):
        # Long `--user` is overwhelmingly auth-bearing across tools, so
        # the tool-scope gate does NOT apply to it. A `--user user:pass`
        # on an unfamiliar tool is still masked.
        out = redact("custom-tool --user alice:hunter2 some-target")
        assert "hunter2" not in out


class TestSegmentSplitterSeparatorAtomicity:
    """Codex review cycle 3 finding 1: the splitter used to revisit the
    second ``&`` of ``&&``, which the new segment-reconstructor in
    ``_unquote_options_in_credential_segments`` would emit as a stray
    extra ``&`` in the output. The splitter now consumes multi-character
    separators atomically."""

    def test_double_amp_separator_is_preserved_through_quote_unquote(self):
        # `hydra '-p' hunter2 host ssh && echo ok` exercises the
        # reconstruction path: the first segment (hydra) unquotes,
        # the second (echo) does not. The `&&` separator must arrive
        # in the output exactly once, not as `&&&`.
        out = redact("hydra '-p' hunter2 host ssh && echo ok")
        assert "&&&" not in out
        assert "&&" in out
        assert "hunter2" not in out  # still redacted
        assert "echo ok" in out

    def test_double_pipe_separator_is_preserved(self):
        out = redact("hydra '-p' hunter2 host ssh || echo failed")
        assert out.count("||") == 1
        assert "hunter2" not in out


class TestArgvShortFlagRedaction:
    """Codex review cycle 3 finding 2: structured argv arrays bypassed
    the new short-flag redactors (which only ran on scalar command
    strings). ``redact()`` now detects an argv whose leading token
    names a credential-family tool and applies the same short-flag
    rules per-element."""

    def test_argv_hydra_short_p(self):
        out = redact(["hydra", "-p", "hunter2", "host", "ssh"])
        assert out == ["hydra", "-p", REDACTED, "host", "ssh"]

    def test_argv_curl_short_u_credential(self):
        out = redact(["curl", "-u", "alice:hunter2", "https://target/"])
        assert out == ["curl", "-u", REDACTED, "https://target/"]

    def test_argv_curl_short_u_bare_username_preserved(self):
        # Bare username (no `:`/`%`) stays — content-based gate still applies.
        out = redact(["curl", "-u", "alice", "https://target/"])
        assert out == ["curl", "-u", "alice", "https://target/"]

    def test_argv_ldapsearch_short_w(self):
        out = redact(["ldapsearch", "-x", "-D", "cn=admin,dc=lab", "-w", "hunter2"])
        assert "hunter2" not in out
        assert out[-2] == "-w"
        assert out[-1] == REDACTED

    def test_argv_nxc_short_h_hash(self):
        out = redact(["nxc", "smb", "dc.example", "-u", "alice", "-H", "AAD3:8846"])
        # `-u alice` bare → preserved.
        assert "alice" in out
        # `-H AAD3:8846` → redacted.
        assert "AAD3:8846" not in out
        h_idx = out.index("-H")
        assert out[h_idx + 1] == REDACTED

    def test_argv_nmap_short_p_port_preserved(self):
        # nmap is not a credential tool; -p 22 is a port spec.
        out = redact(["nmap", "-p", "22", "10.0.0.1"])
        assert out == ["nmap", "-p", "22", "10.0.0.1"]

    def test_argv_long_flag_pair_still_works(self):
        # The pre-existing pair-form for long sensitive flags still works.
        out = redact(["whatever", "--password", "hunter2"])
        assert out == ["whatever", "--password", REDACTED]

    def test_argv_inside_dict_value_is_redacted(self):
        out = redact({"args": ["hydra", "-p", "hunter2", "host", "ssh"], "rc": 0})
        assert out["args"] == ["hydra", "-p", REDACTED, "host", "ssh"]
        assert out["rc"] == 0


class TestExperimentNoRedactToggle:
    """``APTL_EXPERIMENT_NO_REDACT`` does NOT affect the shared
    :func:`redact` primitive (codex pre-push cycle 3 finding-9 —
    routing it through ``redact()`` would disable OTel/Tempo, runstore,
    stderr, snapshot, and CLI redaction). The toggle is consulted
    ONLY via the public :func:`experiment_no_redact_active` accessor,
    and only by the local per-run capture sink wrappers (e.g.
    ``mcp-red/src/capture.ts buildCaptureRecord``).
    """

    def test_redact_always_redacts_regardless_of_toggle(self, monkeypatch):
        from aptl.utils.redaction import experiment_no_redact_active

        # Toggle on → accessor reports True, but ``redact`` itself
        # stays redact-on (this is the critical invariant).
        monkeypatch.setenv("APTL_EXPERIMENT_NO_REDACT", "1")
        assert experiment_no_redact_active() is True
        assert redact({"password": "hunter2"}) == {"password": REDACTED}

        # Toggle off → accessor reports False, ``redact`` still redact-on.
        monkeypatch.delenv("APTL_EXPERIMENT_NO_REDACT", raising=False)
        assert experiment_no_redact_active() is False
        assert redact({"password": "hunter2"}) == {"password": REDACTED}

    def test_accessor_unset_default_returns_false(self, monkeypatch):
        from aptl.utils.redaction import experiment_no_redact_active

        monkeypatch.delenv("APTL_EXPERIMENT_NO_REDACT", raising=False)
        assert experiment_no_redact_active() is False

    @pytest.mark.parametrize("val", ["1", "true", "TRUE", "yes", "Yes", "on", "ON"])
    def test_accessor_truthy_returns_true(self, monkeypatch, val):
        from aptl.utils.redaction import experiment_no_redact_active

        monkeypatch.setenv("APTL_EXPERIMENT_NO_REDACT", val)
        assert experiment_no_redact_active() is True

    @pytest.mark.parametrize("val", ["0", "", "false", "False", "no", "off", "anything"])
    def test_accessor_falsy_returns_false(self, monkeypatch, val):
        from aptl.utils.redaction import experiment_no_redact_active

        monkeypatch.setenv("APTL_EXPERIMENT_NO_REDACT", val)
        assert experiment_no_redact_active() is False

    def test_accessor_is_read_per_call(self, monkeypatch):
        from aptl.utils.redaction import experiment_no_redact_active

        monkeypatch.setenv("APTL_EXPERIMENT_NO_REDACT", "1")
        assert experiment_no_redact_active() is True
        monkeypatch.delenv("APTL_EXPERIMENT_NO_REDACT")
        assert experiment_no_redact_active() is False


class TestRedactorBounds:
    """Defense-in-depth bounds on the redactor itself (issue #386, ARCH-386-01).

    These guard against the redaction layer becoming a denial-of-service
    (catastrophic regex backtracking) or a fail-open crash (RecursionError)
    when fed hostile or pathological control-plane artifacts. Both bounds
    fail CLOSED — they over-redact, never leak.
    """

    # A CPU-time budget that cleanly separates the linear path (milliseconds of
    # CPU) from a reintroduced O(n^2) backtracking regression (tens of seconds
    # of CPU at these input sizes). Measured with process CPU time, not wall
    # clock: an oversubscribed host that starves this process of scheduler time
    # inflates wall-clock duration even for the linear path and would flake the
    # test, whereas catastrophic backtracking burns CPU — which process_time
    # captures and scheduling delay does not.
    _BUDGET_S = 3.0

    def _redact_within_budget(self, value):
        import time

        start = time.process_time()
        out = redact(value)
        return out, time.process_time() - start

    def test_impacket_positional_no_at_is_linear_not_redos(self):
        # `user:value` with no terminating `@`: before the fix this drove
        # `_IMPACKET_POSITIONAL_*` into O(n^2) backtracking. Stay under
        # _MAX_SCAN_LEN so the pattern actually runs (the cap doesn't mask it).
        payload = "impacket-psexec " + "a" * 20000 + ":" + "b" * 20000
        _, elapsed = self._redact_within_budget(payload)
        assert elapsed < self._BUDGET_S

    def test_long_flag_token_is_linear_not_redos(self):
        payload = "hydra " + "--" + "a" * 40000 + " target"
        _, elapsed = self._redact_within_budget(payload)
        assert elapsed < self._BUDGET_S

    def test_impacket_positional_still_redacted(self):
        # The ReDoS fix must not weaken redaction of valid targets.
        assert (
            redact("psexec.py corp/alice:S3cr3t@dc01.lab.local x")
            == "psexec.py corp/alice:[REDACTED]@dc01.lab.local x"
        )
        assert redact("psexec.py alice:b:c@host") == "psexec.py alice:[REDACTED]@host"
        # A target whose segment names no impacket tool is left alone.
        assert redact("echo hello:world@notatool") == "echo hello:world@notatool"

    def test_oversized_input_is_bounded_and_still_redacts_linear_secrets(self):
        from aptl.utils.redaction import _MAX_SCAN_LEN

        payload = (
            "psexec.py " + "a" * 90000 + ":" + "b" * 90000 + " password=hunter2"
        )
        assert len(payload) > _MAX_SCAN_LEN
        out, elapsed = self._redact_within_budget(payload)
        assert elapsed < self._BUDGET_S
        # Linear key/value redaction still applies above the cap...
        assert "password=hunter2" not in out
        assert f"password={REDACTED}" in out

    def test_deep_dict_fails_closed_without_recursionerror(self):
        from aptl.utils.redaction import _MAX_DEPTH

        root = node = {}
        for _ in range(_MAX_DEPTH + 50):
            node["n"] = {}
            node = node["n"]
        node["password"] = "should-never-survive"
        out = redact(root)  # must not raise RecursionError
        serialized = json.dumps(out)
        # Fail-closed: the subtree past the depth cap collapses to the marker,
        # so the deep secret is over-redacted rather than leaked.
        assert "should-never-survive" not in serialized
        assert REDACTED in serialized

    def test_deep_list_fails_closed_without_recursionerror(self):
        from aptl.utils.redaction import _MAX_DEPTH

        root = cur = []
        for _ in range(_MAX_DEPTH + 50):
            nxt = []
            cur.append(nxt)
            cur = nxt
        cur.append("token=should-never-survive")
        out = redact(root)  # must not raise RecursionError
        assert "should-never-survive" not in json.dumps(out)

    def test_shallow_nesting_below_cap_is_unaffected(self):
        # A structure well within the cap redacts normally end-to-end.
        nested = {"a": {"b": {"c": {"password": "hunter2", "host": "dc01"}}}}
        assert redact(nested) == {
            "a": {"b": {"c": {"password": REDACTED, "host": "dc01"}}}
        }

    def test_bytes_values_are_redacted_not_bypassed(self):
        # bytes/bytearray previously fell through unredacted (redact-03).
        assert redact(b"password=hunter2") == f"password={REDACTED}"
        assert redact(bytearray(b"token: abc")) == f"token: {REDACTED}"
        # Non-UTF-8 bytes decode with replacement and still redact embedded kv.
        assert f"pass={REDACTED}" in redact(b"\xff\xfepass=\x00secret")

    def test_bytes_in_container_are_redacted(self):
        out = redact({"blob": b"api_key=AKIA1234567890"})
        assert out == {"blob": f"api_key={REDACTED}"}
