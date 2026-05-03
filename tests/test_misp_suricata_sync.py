"""Unit tests for the MISP-to-Suricata IOC sync service.

ADR-019 invariant: generated rules must always use ``alert`` action.
The translator MUST never emit ``drop``/``reject`` regardless of input.
"""

from __future__ import annotations

import json
import logging
import socket
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestMispAttributeModel:
    """Pydantic DTO for an inbound MISP attribute."""

    def test_accepts_minimal_attribute(self):
        from aptl.services.misp_suricata_sync.models import MispAttribute

        attr = MispAttribute(type="ip-dst", value="198.51.100.42")
        assert attr.type == "ip-dst"
        assert attr.value == "198.51.100.42"
        assert attr.event_id is None

    def test_carries_optional_event_id(self):
        from aptl.services.misp_suricata_sync.models import MispAttribute

        attr = MispAttribute(type="ip-dst", value="198.51.100.42", event_id="42")
        assert attr.event_id == "42"

    def test_rejects_empty_value(self):
        from aptl.services.misp_suricata_sync.models import MispAttribute

        with pytest.raises(ValidationError):
            MispAttribute(type="ip-dst", value="")

    def test_rejects_empty_type(self):
        from aptl.services.misp_suricata_sync.models import MispAttribute

        with pytest.raises(ValidationError):
            MispAttribute(type="", value="198.51.100.42")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


class TestServiceConfig:
    def test_loads_defaults_with_required_api_key(self, monkeypatch):
        from aptl.services.misp_suricata_sync.config import ServiceConfig

        monkeypatch.setenv("MISP_API_KEY", "test-key")
        for var in (
            "MISP_URL", "MISP_VERIFY_SSL", "IOC_TAG_FILTER",
            "SYNC_INTERVAL_SECONDS", "RULES_OUT_PATH",
            "SURICATA_SOCKET_PATH", "SID_BASE", "LOG_LEVEL",
        ):
            monkeypatch.delenv(var, raising=False)

        cfg = ServiceConfig.from_env()
        assert cfg.misp_url == "https://misp"
        assert cfg.misp_api_key == "test-key"
        assert cfg.misp_verify_ssl is False
        assert cfg.ioc_tag_filter == "aptl:enforce"
        assert cfg.sync_interval_seconds == 300
        # Default lives well above ET Open's 2.x million range; see
        # translator.py's _SID_OFFSET_MASK rationale.
        assert cfg.sid_base == 99_000_000
        assert cfg.log_level == "INFO"

    def test_rejects_missing_api_key(self, monkeypatch):
        from aptl.services.misp_suricata_sync.config import ServiceConfig

        monkeypatch.delenv("MISP_API_KEY", raising=False)
        with pytest.raises(ValueError):
            ServiceConfig.from_env()

    def test_rejects_empty_api_key(self, monkeypatch):
        from aptl.services.misp_suricata_sync.config import ServiceConfig

        monkeypatch.setenv("MISP_API_KEY", "   ")
        with pytest.raises(ValueError):
            ServiceConfig.from_env()

    def test_rejects_placeholder_api_key(self, monkeypatch):
        """An unmodified .env.example placeholder must fail loudly at
        startup rather than silently running with a known-bogus key."""
        from aptl.services.misp_suricata_sync.config import ServiceConfig

        for placeholder in (
            "PLEASEREPLACEMEPLEASEREPLACEMEPLEASEREPLACE",
            "CHANGE_ME_misp_api_key",
            "changeme",
            "REPLACE_ME_with_real_key",
        ):
            monkeypatch.setenv("MISP_API_KEY", placeholder)
            with pytest.raises(ValidationError):
                ServiceConfig.from_env()

    def test_rejects_interval_below_minimum(self, monkeypatch):
        from aptl.services.misp_suricata_sync.config import ServiceConfig

        monkeypatch.setenv("MISP_API_KEY", "k")
        monkeypatch.setenv("SYNC_INTERVAL_SECONDS", "5")
        with pytest.raises(ValidationError):
            ServiceConfig.from_env()

    def test_rejects_sid_base_outside_range(self, monkeypatch):
        from aptl.services.misp_suricata_sync.config import ServiceConfig

        monkeypatch.setenv("MISP_API_KEY", "k")
        # Below the lower bound (would land inside ET Open's 2.x million band).
        monkeypatch.setenv("SID_BASE", "999")
        with pytest.raises(ValidationError):
            ServiceConfig.from_env()

    def test_rejects_sid_base_that_overflows_documented_band(self, monkeypatch):
        """SID_BASE + 24-bit offset must stay below 2_000_000_000. A
        too-large base would push generated SIDs into a region the
        translator's offset arithmetic was never validated against."""
        from aptl.services.misp_suricata_sync.config import ServiceConfig

        monkeypatch.setenv("MISP_API_KEY", "k")
        monkeypatch.setenv("SID_BASE", str(1_999_999_999))
        with pytest.raises(ValidationError):
            ServiceConfig.from_env()

    def test_rejects_typo_in_verify_ssl(self, monkeypatch):
        """A typo like ``MISP_VERIFY_SSL=ture`` previously fell through
        silently to ``False``, turning a typo into a security regression.
        The strict parser now raises."""
        from aptl.services.misp_suricata_sync.config import ServiceConfig

        monkeypatch.setenv("MISP_API_KEY", "k")
        monkeypatch.setenv("MISP_VERIFY_SSL", "ture")
        with pytest.raises(ValueError):
            ServiceConfig.from_env()

    def test_accepts_custom_overrides(self, monkeypatch):
        from aptl.services.misp_suricata_sync.config import ServiceConfig

        monkeypatch.setenv("MISP_API_KEY", "k")
        monkeypatch.setenv("MISP_URL", "https://misp.lab")
        monkeypatch.setenv("MISP_VERIFY_SSL", "true")
        monkeypatch.setenv("MISP_CA_CERT_PATH", "/etc/aptl/lab-ca.pem")
        monkeypatch.setenv("IOC_TAG_FILTER", "tlp:white")
        monkeypatch.setenv("SYNC_INTERVAL_SECONDS", "60")
        monkeypatch.setenv("SID_BASE", "150000000")
        cfg = ServiceConfig.from_env()
        assert cfg.misp_url == "https://misp.lab"
        assert cfg.misp_verify_ssl is True
        assert cfg.misp_ca_cert_path == Path("/etc/aptl/lab-ca.pem")
        assert cfg.ioc_tag_filter == "tlp:white"
        assert cfg.sync_interval_seconds == 60
        assert cfg.sid_base == 150_000_000

    def test_ca_cert_path_defaults_to_none(self, monkeypatch):
        from aptl.services.misp_suricata_sync.config import ServiceConfig

        monkeypatch.setenv("MISP_API_KEY", "k")
        monkeypatch.delenv("MISP_CA_CERT_PATH", raising=False)
        cfg = ServiceConfig.from_env()
        assert cfg.misp_ca_cert_path is None

    def test_ca_cert_path_blank_treated_as_none(self, monkeypatch):
        """The compose default is the empty string when not overridden — the
        loader must treat that as 'no CA configured' and not as Path('')."""
        from aptl.services.misp_suricata_sync.config import ServiceConfig

        monkeypatch.setenv("MISP_API_KEY", "k")
        monkeypatch.setenv("MISP_CA_CERT_PATH", "   ")
        cfg = ServiceConfig.from_env()
        assert cfg.misp_ca_cert_path is None


# ---------------------------------------------------------------------------
# Translator
# ---------------------------------------------------------------------------


def _attr(type_: str, value: str, event_id: str | None = None):
    from aptl.services.misp_suricata_sync.models import MispAttribute

    return MispAttribute(type=type_, value=value, event_id=event_id)


def _make_translator(**overrides):
    from aptl.services.misp_suricata_sync.translator import IocTranslator

    kwargs = dict(sid_base=99_000_000)
    kwargs.update(overrides)
    return IocTranslator(**kwargs)


class TestTranslator:
    def test_ip_src_emits_source_side_alert_ip_rule(self):
        result = _make_translator().translate([_attr("ip-src", "198.51.100.42")])
        assert len(result.rules) == 1
        rule = result.rules[0].text
        assert rule.startswith("alert ip 198.51.100.42 any -> any any (")
        assert "sid:" in rule
        assert "rev:1" in rule

    def test_ip_dst_emits_destination_side_alert_ip_rule(self):
        result = _make_translator().translate([_attr("ip-dst", "203.0.113.7")])
        rule = result.rules[0].text
        assert rule.startswith("alert ip any any -> 203.0.113.7 any (")

    def test_domain_emits_dns_query_rule(self):
        result = _make_translator().translate([_attr("domain", "evil.example.com")])
        rule = result.rules[0].text
        assert rule.startswith("alert dns any any -> any any (")
        assert "dns.query" in rule
        assert 'content:"evil.example.com"' in rule
        assert "nocase" in rule
        # ``dotprefix`` + ``endswith`` together anchor the match so
        # "evil.example.com" matches itself and subdomains but does NOT
        # match "notevil.example.com" or "evil.example.com.evil".
        assert "dotprefix" in rule
        assert "endswith" in rule

    def test_http_url_with_path_emits_host_and_uri_match(self):
        result = _make_translator().translate(
            [_attr("url", "http://evil.example.com/payload")]
        )
        rule = result.rules[0].text
        assert rule.startswith("alert http any any -> any any (")
        assert 'http.host; content:"evil.example.com"' in rule
        assert 'http.uri; content:"/payload"' in rule
        assert "dotprefix" in rule  # anchored host match
        assert "endswith" in rule

    def test_http_url_with_only_host_emits_host_match_only(self):
        """Host-only URL must not generate `content:"/"` (false-positive bait)."""
        result = _make_translator().translate(
            [_attr("url", "http://evil.example.com")]
        )
        rule = result.rules[0].text
        assert 'http.host; content:"evil.example.com"' in rule
        assert "http.uri" not in rule
        assert 'content:"/"' not in rule

    def test_http_url_with_root_path_skips_uri_match(self):
        result = _make_translator().translate(
            [_attr("url", "http://evil.example.com/")]
        )
        rule = result.rules[0].text
        assert "http.uri" not in rule

    def test_http_url_with_query_preserves_query_in_uri_match(self):
        result = _make_translator().translate(
            [_attr("url", "http://evil.example.com/path?id=1&x=2")]
        )
        rule = result.rules[0].text
        assert 'http.uri; content:"/path?id=1&x=2"' in rule

    def test_https_url_emits_tls_sni_rule_not_http_uri(self):
        """HTTPS URI bytes are encrypted; the IDS can only see SNI. The
        translator MUST emit a TLS SNI rule, not a dead http rule."""
        result = _make_translator().translate(
            [_attr("url", "https://user:pass@evil.example.com:8443/payload")]
        )
        rule = result.rules[0].text
        assert rule.startswith("alert tls any any -> any any (")
        assert "tls.sni" in rule
        assert 'content:"evil.example.com"' in rule
        # urlparse strips userinfo and port from .hostname.
        sni_match = rule.split("tls.sni", 1)[1].split("sid:", 1)[0]
        assert "user" not in sni_match
        assert "8443" not in sni_match
        # Path is not observable on HTTPS — must not appear in the rule.
        assert "http.uri" not in rule
        assert "/payload" not in sni_match

    def test_url_lowercases_host(self):
        result = _make_translator().translate(
            [_attr("url", "http://EVIL.Example.COM/x")]
        )
        rule = result.rules[0].text
        assert 'http.host; content:"evil.example.com"' in rule

    def test_url_without_scheme_still_parses_host(self):
        result = _make_translator().translate(
            [_attr("url", "evil.example.com/payload")]
        )
        rule = result.rules[0].text
        assert 'http.host; content:"evil.example.com"' in rule
        assert 'http.uri; content:"/payload"' in rule

    def test_https_and_http_url_with_same_host_get_distinct_sids(self):
        """Different schemes for the same host produce different rules with
        distinct SIDs (no SID collision warning)."""
        result = _make_translator().translate(
            [
                _attr("url", "http://evil.example.com/x"),
                _attr("url", "https://evil.example.com/x"),
            ]
        )
        assert len(result.rules) == 2
        sids = {r.sid for r in result.rules}
        assert len(sids) == 2

    def test_url_with_no_host_skipped_with_warning(self, caplog):
        caplog.set_level(logging.WARNING, logger="aptl.misp_suricata_sync")
        # MispAttribute rejects empty values, so use a value that parses to
        # an empty hostname instead.
        result = _make_translator().translate([_attr("url", "/just-a-path")])
        assert all(r.attribute_type != "url" for r in result.rules)

    def test_ip_src_skipped_when_not_a_valid_ip(self, caplog):
        caplog.set_level(logging.WARNING, logger="aptl.misp_suricata_sync")
        result = _make_translator().translate(
            [_attr("ip-src", "not-an-ip"), _attr("ip-src", "203.0.113.7")]
        )
        assert len(result.rules) == 1
        assert "203.0.113.7" in result.rules[0].text
        assert any(
            "malformed ip-src" in r.message.lower() for r in caplog.records
        )

    def test_ip_dst_accepts_ipv6_address(self):
        result = _make_translator().translate(
            [_attr("ip-dst", "2001:db8::1")]
        )
        assert len(result.rules) == 1
        assert "2001:db8::1" in result.rules[0].text

    @pytest.mark.parametrize(
        "hash_type, digest_len, keyword",
        [
            ("md5", 32, "filemd5"),
            ("sha1", 40, "filesha1"),
            ("sha256", 64, "filesha256"),
        ],
    )
    def test_hash_collected_into_per_type_sidecar_list(
        self, hash_type, digest_len, keyword
    ):
        h = "a" * digest_len
        result = _make_translator().translate([_attr(hash_type, h)])
        assert result.hash_lists == {hash_type: [h]}
        assert len(result.rules) == 1
        rule = result.rules[0].text
        # Path is relative to Suricata's default-rule-path so the
        # documented filemd5/filesha1/filesha256 lookup works.
        assert f"{keyword}:misp/misp-{hash_type}.list" in rule
        assert h not in rule  # the hash itself lives in the sidecar list

    def test_malformed_hash_skipped_with_warning(self, caplog):
        caplog.set_level(logging.WARNING, logger="aptl.misp_suricata_sync")
        result = _make_translator().translate(
            [
                _attr("sha256", "tooshort"),
                _attr("md5", "z" * 32),  # right length but not hex
                _attr("sha1", "c" * 40),  # valid
            ]
        )
        assert result.hash_lists == {"sha1": ["c" * 40]}
        # No sha256 / md5 entries because both were rejected.
        assert all(
            r.attribute_type != "sha256" for r in result.rules
        ), result.rules
        assert all(
            r.attribute_type != "md5" for r in result.rules
        ), result.rules
        assert any(
            "malformed sha256" in r.message.lower() for r in caplog.records
        )

    def test_hash_normalised_to_lowercase(self):
        h_upper = "A" * 64
        result = _make_translator().translate([_attr("sha256", h_upper)])
        assert result.hash_lists == {"sha256": ["a" * 64]}

    def test_one_hash_rule_emitted_per_type_regardless_of_count(self):
        attrs = [
            _attr("sha256", "a" * 64),
            _attr("sha256", "b" * 64),
            _attr("md5", "c" * 32),
            _attr("md5", "d" * 32),
            _attr("md5", "e" * 32),
        ]
        result = _make_translator().translate(attrs)
        hash_rules = [r for r in result.rules if r.attribute_type in ("md5", "sha1", "sha256")]
        assert len(hash_rules) == 2  # one per type, despite 5 IOCs
        assert sorted(result.hash_lists.keys()) == ["md5", "sha256"]
        assert len(result.hash_lists["md5"]) == 3
        assert len(result.hash_lists["sha256"]) == 2

    def test_unsupported_type_skipped_with_warning(self, caplog):
        caplog.set_level(logging.WARNING, logger="aptl.misp_suricata_sync")
        result = _make_translator().translate(
            [
                _attr("regkey", "HKLM\\Software\\Foo"),
                _attr("ip-dst", "198.51.100.1"),
            ]
        )
        assert len(result.rules) == 1
        assert result.rules[0].attribute_type == "ip-dst"
        assert any("regkey" in r.message for r in caplog.records)

    def test_action_is_always_alert_never_drop(self):
        """ADR-019 invariant: no drop/reject rules under any input."""
        attrs = [
            _attr("ip-src", "1.2.3.4"),
            _attr("ip-dst", "5.6.7.8"),
            _attr("domain", "x.y"),
            _attr("url", "http://x.y/z"),
            _attr("sha256", "d" * 64),
            _attr("md5", "e" * 32),
            _attr("sha1", "f" * 40),
        ]
        result = _make_translator().translate(attrs)
        for r in result.rules:
            assert r.text.startswith("alert "), r.text
            assert "drop " not in r.text
            assert "reject" not in r.text

    def test_sid_is_deterministic_across_runs(self):
        a = [_attr("ip-dst", "198.51.100.42")]
        sids1 = [r.sid for r in _make_translator().translate(a).rules]
        sids2 = [r.sid for r in _make_translator().translate(a).rules]
        assert sids1 == sids2

    def test_sid_collision_drops_second_with_warning(self, caplog, monkeypatch):
        """When two distinct IOCs hash to the same SID, only one rule emits."""
        from aptl.services.misp_suricata_sync import translator as tmod

        monkeypatch.setattr(tmod, "_crc32_sid_offset", lambda type_, value: 7)
        caplog.set_level(logging.WARNING, logger="aptl.misp_suricata_sync")
        result = _make_translator().translate(
            [
                _attr("ip-dst", "198.51.100.1"),
                _attr("ip-dst", "198.51.100.2"),
            ]
        )
        assert len(result.rules) == 1
        assert any("collision" in r.message.lower() for r in caplog.records)

    def test_output_is_sorted_for_stable_render(self):
        attrs_a = [
            _attr("ip-dst", "198.51.100.2"),
            _attr("ip-dst", "198.51.100.1"),
        ]
        attrs_b = list(reversed(attrs_a))
        text_a = [r.text for r in _make_translator().translate(attrs_a).rules]
        text_b = [r.text for r in _make_translator().translate(attrs_b).rules]
        assert text_a == text_b

    def test_hash_list_ordering_is_deterministic(self):
        attrs_a = [_attr("md5", "a" * 32), _attr("md5", "b" * 32)]
        attrs_b = list(reversed(attrs_a))
        out_a = _make_translator().translate(attrs_a).hash_lists
        out_b = _make_translator().translate(attrs_b).hash_lists
        assert out_a == out_b

    def test_escapes_non_alnum_in_content_via_pipe_hex(self):
        result = _make_translator().translate([_attr("domain", "ev\"il.example.com")])
        text = result.rules[0].text
        assert '"' not in text.split('content:"', 1)[1].split('"', 1)[0]
        assert "|22|" in text

    def test_rejects_quote_or_semicolon_in_value_via_escape(self):
        """Even with hostile attribute values, the rule must remain syntactically clean."""
        result = _make_translator().translate(
            [_attr("domain", 'a"; sid:1; rev:1; reference:foo,bar; msg:"x')]
        )
        rule = result.rules[0].text
        # Exactly one trailing semicolon set; only one sid: directive.
        assert rule.count("sid:") == 1
        assert rule.count("msg:") == 1

    def test_event_id_recorded_in_metadata_when_present(self):
        result = _make_translator().translate(
            [_attr("ip-dst", "198.51.100.42", event_id="42")]
        )
        assert "metadata:misp_event_id 42" in result.rules[0].text

    def test_event_id_omitted_when_absent(self):
        result = _make_translator().translate([_attr("ip-dst", "198.51.100.42")])
        assert "metadata:" not in result.rules[0].text

    def test_non_numeric_event_id_omitted_with_warning(self, caplog):
        """A malformed event_id must not splice into the rule file (would
        break Suricata reload). Drop with warning."""
        caplog.set_level(logging.WARNING, logger="aptl.misp_suricata_sync")
        result = _make_translator().translate(
            [_attr("ip-dst", "198.51.100.42", event_id="42; sid:1; ;")]
        )
        rule = result.rules[0].text
        assert "metadata:" not in rule
        assert any(
            "non-numeric event_id" in r.message.lower() for r in caplog.records
        )

    def test_sids_stay_within_documented_band(self):
        """SID_BASE + 24-bit offset ⇒ generated SIDs fall in
        [SID_BASE, SID_BASE + 0xFFFFFF]. The default 99_000_000 + ~16M
        keeps the band entirely outside ET Open's 2.x million range."""
        attrs = [
            _attr("ip-dst", f"198.51.100.{i}") for i in range(1, 50)
        ] + [
            _attr("domain", f"e{i}.example.com") for i in range(1, 50)
        ]
        result = _make_translator(sid_base=99_000_000).translate(attrs)
        for r in result.rules:
            assert 99_000_000 <= r.sid <= 99_000_000 + 0xFFFFFF, r.sid


class TestRenderRulesFile:
    def test_header_records_metadata(self):
        from aptl.services.misp_suricata_sync.translator import render_rules_file

        result = _make_translator().translate([_attr("ip-dst", "198.51.100.42")])
        text = render_rules_file(
            result.rules,
            misp_url="https://misp.lab",
            tag_filter="aptl:enforce",
            sid_base=99_000_000,
        )
        assert "# APTL MISP-to-Suricata sync" in text
        assert "https://misp.lab" in text
        assert "aptl:enforce" in text
        assert "ioc_count=1" in text
        assert "alert ip any any -> 198.51.100.42" in text

    def test_header_has_no_timestamp_so_render_is_idempotent(self):
        """If the header carried a timestamp, write_if_changed would always
        rewrite the file and trigger spurious Suricata reloads."""
        from aptl.services.misp_suricata_sync.translator import render_rules_file

        result = _make_translator().translate([_attr("ip-dst", "198.51.100.42")])
        text = render_rules_file(
            result.rules,
            misp_url="https://misp.lab",
            tag_filter="aptl:enforce",
            sid_base=99_000_000,
        )
        assert "generated_at" not in text

    def test_empty_rules_still_renders_header(self):
        from aptl.services.misp_suricata_sync.translator import render_rules_file

        text = render_rules_file(
            [],
            misp_url="https://misp.lab",
            tag_filter="aptl:enforce",
            sid_base=99_000_000,
        )
        assert "ioc_count=0" in text


class TestRenderHashListFile:
    def test_renders_one_hash_per_line_sorted_and_deduped(self):
        from aptl.services.misp_suricata_sync.translator import render_hash_list_file

        text = render_hash_list_file(
            "sha256",
            ["b" * 64, "a" * 64, "a" * 64],
        )
        lines = text.splitlines()
        # First two lines are the comment header.
        assert lines[0].startswith("#")
        assert lines[1].startswith("#")
        # Body is sorted + deduped.
        assert lines[2:] == ["a" * 64, "b" * 64]


# ---------------------------------------------------------------------------
# Rule writer
# ---------------------------------------------------------------------------


class TestWriteIfChanged:
    """Tests for the atomic, idempotent rule-file writer."""


    def test_creates_file_when_missing(self, tmp_path: Path):
        from aptl.services.misp_suricata_sync.rule_writer import write_if_changed

        target = tmp_path / "misp-iocs.rules"
        assert write_if_changed(target, "hello\n") is True
        assert target.read_text() == "hello\n"

    def test_returns_false_when_content_identical(self, tmp_path: Path):
        from aptl.services.misp_suricata_sync.rule_writer import write_if_changed

        target = tmp_path / "misp-iocs.rules"
        target.write_text("same\n")
        assert write_if_changed(target, "same\n") is False

    def test_returns_true_and_replaces_when_different(self, tmp_path: Path):
        from aptl.services.misp_suricata_sync.rule_writer import write_if_changed

        target = tmp_path / "misp-iocs.rules"
        target.write_text("old\n")
        assert write_if_changed(target, "new\n") is True
        assert target.read_text() == "new\n"

    def test_atomic_write_uses_temp_then_rename(self, tmp_path: Path, mocker):
        from aptl.services.misp_suricata_sync.rule_writer import write_if_changed

        target = tmp_path / "misp-iocs.rules"
        target.write_text("old\n")
        spy = mocker.spy(Path, "replace")
        write_if_changed(target, "new\n")
        assert spy.call_count == 1

    def test_creates_parent_directory_if_missing(self, tmp_path: Path):
        from aptl.services.misp_suricata_sync.rule_writer import write_if_changed

        target = tmp_path / "nested" / "misp-iocs.rules"
        assert write_if_changed(target, "x\n") is True
        assert target.read_text() == "x\n"

    def test_does_not_truncate_when_caller_passes_none(self, tmp_path: Path):
        from aptl.services.misp_suricata_sync.rule_writer import write_if_changed

        target = tmp_path / "misp-iocs.rules"
        target.write_text("preserved\n")
        with pytest.raises(TypeError):
            write_if_changed(target, None)  # type: ignore[arg-type]
        assert target.read_text() == "preserved\n"


# ---------------------------------------------------------------------------
# Suricata reloader
# ---------------------------------------------------------------------------


class _FakeSocket:
    """Minimal in-memory replacement for socket.socket()."""

    def __init__(self, server_messages: list[bytes]):
        self.server_messages = list(server_messages)
        self.sent: list[bytes] = []
        self._buffer = b""
        self.closed = False

    def settimeout(self, _t: float) -> None:
        pass

    def connect(self, _path: str) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)
        if self.server_messages:
            self._buffer += self.server_messages.pop(0)

    def recv(self, n: int) -> bytes:
        if not self._buffer:
            return b""
        chunk = self._buffer[:n]
        self._buffer = self._buffer[n:]
        return chunk

    def close(self) -> None:
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class TestSuricataReloader:
    def test_handshake_then_reload_command(self, mocker, tmp_path: Path):
        from aptl.services.misp_suricata_sync.suricata_reloader import (
            SuricataReloader,
        )

        fake = _FakeSocket(
            [
                json.dumps({"return": "OK"}).encode() + b"\n",
                json.dumps({"return": "OK", "message": "done"}).encode() + b"\n",
            ]
        )
        mocker.patch.object(socket, "socket", return_value=fake)

        sock_path = tmp_path / "suricata-command.socket"
        reloader = SuricataReloader(sock_path)
        result = reloader.reload_rules()
        assert result is True
        # Two messages: version handshake + reload-rules command.
        assert len(fake.sent) == 2
        handshake = json.loads(fake.sent[0].decode().rstrip())
        cmd = json.loads(fake.sent[1].decode().rstrip())
        assert "version" in handshake
        assert cmd == {"command": "reload-rules"}

    def test_returns_false_when_socket_missing(self, mocker, tmp_path: Path, caplog):
        from aptl.services.misp_suricata_sync.suricata_reloader import (
            SuricataReloader,
        )

        bad_sock = MagicMock()
        bad_sock.__enter__.return_value = bad_sock
        bad_sock.__exit__.return_value = False
        bad_sock.connect.side_effect = FileNotFoundError("socket missing")
        mocker.patch.object(socket, "socket", return_value=bad_sock)

        caplog.set_level(logging.WARNING, logger="aptl.misp_suricata_sync")
        reloader = SuricataReloader(tmp_path / "missing.socket")
        assert reloader.reload_rules() is False
        assert any("reload" in r.message.lower() for r in caplog.records)

    def test_returns_false_on_handshake_failure_response(
        self, mocker, tmp_path: Path
    ):
        from aptl.services.misp_suricata_sync.suricata_reloader import (
            SuricataReloader,
        )

        fake = _FakeSocket(
            [json.dumps({"return": "NOK", "message": "bad version"}).encode() + b"\n"]
        )
        mocker.patch.object(socket, "socket", return_value=fake)
        reloader = SuricataReloader(tmp_path / "sock")
        assert reloader.reload_rules() is False


# ---------------------------------------------------------------------------
# MISP client
# ---------------------------------------------------------------------------


class TestMispClient:
    def _cfg(self, **overrides):
        from aptl.services.misp_suricata_sync.config import ServiceConfig

        defaults = dict(
            misp_url="https://misp",
            misp_api_key="test-key",
            misp_verify_ssl=False,
            misp_ca_cert_path=None,
            ioc_tag_filter="aptl:enforce",
            sync_interval_seconds=300,
            rules_out_path=Path("/tmp/misp-iocs.rules"),
            suricata_socket_path=Path("/tmp/suricata.sock"),
            sid_base=99_000_000,
            log_level="INFO",
        )
        defaults.update(overrides)
        return ServiceConfig(**defaults)

    @patch("aptl.services.misp_suricata_sync.misp_client._curl_json")
    def test_sends_authorization_header_as_bare_key(self, mock_curl):
        from aptl.services.misp_suricata_sync.misp_client import MispClient

        mock_curl.return_value = {"response": {"Attribute": []}}
        MispClient(self._cfg()).fetch_tagged_attributes()
        kwargs = mock_curl.call_args.kwargs
        assert kwargs["auth_header"] == "test-key"

    @patch("aptl.services.misp_suricata_sync.misp_client._curl_json")
    def test_sends_tag_filter_in_body(self, mock_curl):
        from aptl.services.misp_suricata_sync.misp_client import MispClient

        mock_curl.return_value = {"response": {"Attribute": []}}
        MispClient(self._cfg(ioc_tag_filter="custom:tag")).fetch_tagged_attributes()
        kwargs = mock_curl.call_args.kwargs
        assert "custom:tag" in kwargs["body"]["tags"]

    @patch("aptl.services.misp_suricata_sync.misp_client._curl_json")
    def test_returns_none_on_curl_failure(self, mock_curl):
        from aptl.services.misp_suricata_sync.misp_client import MispClient

        mock_curl.return_value = None
        assert MispClient(self._cfg()).fetch_tagged_attributes() is None

    @patch("aptl.services.misp_suricata_sync.misp_client._curl_json")
    def test_returns_empty_list_when_no_attributes(self, mock_curl):
        from aptl.services.misp_suricata_sync.misp_client import MispClient

        mock_curl.return_value = {"response": {"Attribute": []}}
        result = MispClient(self._cfg()).fetch_tagged_attributes()
        assert result == []

    @patch("aptl.services.misp_suricata_sync.misp_client._curl_json")
    def test_returns_none_on_malformed_envelope(self, mock_curl):
        """Missing/wrong envelope shape must be reported as None, not [].

        Treating it as an empty IOC set would wipe the rule file on API
        drift; the runner must preserve the last-known-good file instead.
        """
        from aptl.services.misp_suricata_sync.misp_client import MispClient

        for malformed in (
            "string-not-dict",
            ["list-not-dict"],
            {},  # no 'response' key
            {"response": "not-a-dict"},
            {"response": {}},  # no 'Attribute' key
            {"response": {"Attribute": "not-a-list"}},
        ):
            mock_curl.return_value = malformed
            result = MispClient(self._cfg()).fetch_tagged_attributes()
            assert result is None, malformed

    @patch("aptl.services.misp_suricata_sync.misp_client._curl_json")
    def test_returns_attributes_parsed_to_dto(self, mock_curl):
        from aptl.services.misp_suricata_sync.misp_client import MispClient

        mock_curl.return_value = {
            "response": {
                "Attribute": [
                    {"type": "ip-dst", "value": "198.51.100.42", "event_id": "42"},
                    {"type": "domain", "value": "evil.example.com"},
                ]
            }
        }
        result = MispClient(self._cfg()).fetch_tagged_attributes()
        assert result is not None
        assert [(a.type, a.value) for a in result] == [
            ("ip-dst", "198.51.100.42"),
            ("domain", "evil.example.com"),
        ]
        assert result[0].event_id == "42"

    @patch("aptl.services.misp_suricata_sync.misp_client._curl_json")
    def test_skips_malformed_attributes(self, mock_curl):
        from aptl.services.misp_suricata_sync.misp_client import MispClient

        mock_curl.return_value = {
            "response": {
                "Attribute": [
                    {"type": "ip-dst", "value": "198.51.100.42"},
                    {"type": "ip-dst"},  # missing value
                    {"value": "x"},  # missing type
                    "garbage",
                ]
            }
        }
        result = MispClient(self._cfg()).fetch_tagged_attributes()
        assert result is not None
        assert len(result) == 1
        assert result[0].value == "198.51.100.42"

    @patch("aptl.services.misp_suricata_sync.misp_client._curl_json")
    def test_wait_for_ready_returns_true_on_success(self, mock_curl):
        from aptl.services.misp_suricata_sync.misp_client import MispClient

        mock_curl.return_value = {"version": "2.4.0"}
        assert MispClient(self._cfg()).wait_for_ready(timeout=1) is True

    @patch("aptl.services.misp_suricata_sync.misp_client._curl_json")
    def test_wait_for_ready_returns_false_on_failure(self, mock_curl):
        from aptl.services.misp_suricata_sync.misp_client import MispClient

        mock_curl.return_value = None
        assert MispClient(self._cfg()).wait_for_ready(timeout=0.1) is False

    @patch("aptl.services.misp_suricata_sync.misp_client._curl_json")
    def test_does_not_log_api_key(self, mock_curl, caplog):
        from aptl.services.misp_suricata_sync.misp_client import MispClient

        caplog.set_level(logging.DEBUG, logger="aptl.misp_suricata_sync")
        mock_curl.return_value = {"response": {"Attribute": []}}
        MispClient(self._cfg(misp_api_key="super-secret-key-XYZ")).fetch_tagged_attributes()
        for record in caplog.records:
            assert "super-secret-key-XYZ" not in record.getMessage()

    @pytest.mark.parametrize(
        "verify_ssl, ca_cert, want_insecure, want_ca_str",
        [
            (False, None, True, None),
            (True, Path("/etc/aptl/lab-ca.pem"), False, "/etc/aptl/lab-ca.pem"),
            (True, None, False, None),
        ],
        ids=["insecure", "verify_with_ca", "verify_system_trust"],
    )
    @patch("aptl.services.misp_suricata_sync.misp_client._curl_json")
    def test_translates_tls_config_to_curl_kwargs(
        self, mock_curl, verify_ssl, ca_cert, want_insecure, want_ca_str
    ):
        from aptl.services.misp_suricata_sync.misp_client import MispClient

        mock_curl.return_value = {"response": {"Attribute": []}}
        MispClient(
            self._cfg(misp_verify_ssl=verify_ssl, misp_ca_cert_path=ca_cert)
        ).fetch_tagged_attributes()
        kwargs = mock_curl.call_args.kwargs
        assert kwargs["insecure"] is want_insecure
        assert kwargs["ca_cert_path"] == want_ca_str


class TestCurlTLSWiring:
    """Direct tests for the secret-safe curl helper.

    Lives in this file because the helper is used by the sync service,
    but it covers the shared ``aptl.utils.curl_safe.curl_json`` directly
    so collectors and any future SOC client get the same guarantees.
    """

    def _run(self, monkeypatch, **kwargs):
        from aptl.utils import curl_safe

        captured: dict = {}

        def fake_run(cmd, *args, **kw):
            captured["cmd"] = list(cmd)
            # Snapshot the contents of any -H @file / -d @file sidecars
            # because they get unlinked before the test sees them.
            for arg in cmd:
                if isinstance(arg, str) and arg.startswith("@"):
                    path = arg[1:]
                    try:
                        with open(path) as fh:
                            captured.setdefault("sidecars", {})[path] = fh.read()
                    except OSError:
                        pass
            return MagicMock(returncode=0, stdout='{"ok":1}', stderr="")

        monkeypatch.setattr(curl_safe.subprocess, "run", fake_run)
        result = curl_safe.curl_json(
            "https://misp/x",
            auth_header=kwargs.get("auth_header", "k"),
            insecure=kwargs.get("insecure", False),
            ca_cert_path=kwargs.get("ca_cert_path"),
            method="GET",
        )
        return captured, result

    @pytest.mark.parametrize(
        "insecure, ca_cert_path, want_dash_k, want_cacert",
        [
            # mode 1: insecure → -k, no --cacert
            (True, None, True, False),
            # mode 2: verify-on with CA bundle → --cacert, no -k
            (False, "/etc/aptl/lab-ca.pem", False, True),
            # mode 3: verify-on, no CA bundle → system trust (neither flag)
            (False, None, False, False),
        ],
        ids=["insecure", "verify_with_ca", "verify_system_trust"],
    )
    def test_tls_argv_matches_posture(
        self, monkeypatch, insecure, ca_cert_path, want_dash_k, want_cacert
    ):
        cap, _ = self._run(
            monkeypatch, insecure=insecure, ca_cert_path=ca_cert_path
        )
        cmd = cap["cmd"]
        assert ("-k" in cmd) is want_dash_k
        assert ("--cacert" in cmd) is want_cacert
        if want_cacert:
            assert ca_cert_path in cmd

    def test_api_key_never_appears_in_argv(self, monkeypatch):
        """The Authorization header — which carries the MISP API key — is
        a high-value secret. It MUST go to curl via `-H @file`, not on
        the command line, so it can't be observed via /proc/*/cmdline or
        ``ps``."""
        cap, _ = self._run(monkeypatch, auth_header="super-secret-XYZ-123")
        cmd = cap["cmd"]
        assert all("super-secret-XYZ-123" not in str(a) for a in cmd), cmd
        # The header file does carry it; it just isn't on argv.
        sidecars = cap.get("sidecars", {})
        assert any(
            "super-secret-XYZ-123" in v for v in sidecars.values()
        ), sidecars


# ---------------------------------------------------------------------------
# Sync loop
# ---------------------------------------------------------------------------


class TestSyncLoop:
    def _cfg(self, tmp_path: Path):
        from aptl.services.misp_suricata_sync.config import ServiceConfig

        return ServiceConfig(
            misp_url="https://misp",
            misp_api_key="k",
            misp_verify_ssl=False,
            misp_ca_cert_path=None,
            ioc_tag_filter="aptl:enforce",
            sync_interval_seconds=300,
            rules_out_path=tmp_path / "misp-iocs.rules",
            suricata_socket_path=tmp_path / "suricata.sock",
            sid_base=99_000_000,
            log_level="INFO",
        )

    def test_skips_write_when_misp_returns_none(self, tmp_path: Path):
        from aptl.services.misp_suricata_sync.main import SyncRunner

        cfg = self._cfg(tmp_path)
        cfg.rules_out_path.write_text("preserved\n")

        client = MagicMock()
        client.fetch_tagged_attributes.return_value = None
        reloader = MagicMock()
        write_fn = MagicMock(return_value=False)

        SyncRunner(
            cfg, client=client, reloader=reloader, write_fn=write_fn
        ).run_once()

        write_fn.assert_not_called()
        reloader.reload_rules.assert_not_called()
        assert cfg.rules_out_path.read_text() == "preserved\n"

    def test_skips_reload_when_writer_reports_no_change(self, tmp_path: Path):
        from aptl.services.misp_suricata_sync.main import SyncRunner
        from aptl.services.misp_suricata_sync.translator import HASH_TYPES

        cfg = self._cfg(tmp_path)
        client = MagicMock()
        client.fetch_tagged_attributes.return_value = []
        reloader = MagicMock()
        write_fn = MagicMock(return_value=False)

        SyncRunner(
            cfg, client=client, reloader=reloader, write_fn=write_fn
        ).run_once()

        # 1 main rule file + one sidecar per HASH_TYPES entry (always
        # written every tick). Use the constant so adding a new hash
        # type doesn't silently break this assertion.
        assert write_fn.call_count == 1 + len(HASH_TYPES)
        reloader.reload_rules.assert_not_called()

    def test_triggers_reload_when_writer_reports_change(self, tmp_path: Path):
        from aptl.services.misp_suricata_sync.main import SyncRunner

        cfg = self._cfg(tmp_path)
        client = MagicMock()
        client.fetch_tagged_attributes.return_value = []
        reloader = MagicMock()
        reloader.reload_rules.return_value = True
        write_fn = MagicMock(return_value=True)

        SyncRunner(
            cfg, client=client, reloader=reloader, write_fn=write_fn
        ).run_once()

        reloader.reload_rules.assert_called_once()

    def test_reload_retried_on_next_tick_after_failure(self, tmp_path: Path):
        """If reload fails after a successful write, the next tick must retry
        even though the file is no longer changing."""
        from aptl.services.misp_suricata_sync.main import SyncRunner
        from aptl.services.misp_suricata_sync.translator import HASH_TYPES

        cfg = self._cfg(tmp_path)
        client = MagicMock()
        client.fetch_tagged_attributes.return_value = []
        reloader = MagicMock()
        reloader.reload_rules.side_effect = [False, True]

        # Tick 1: writer reports change everywhere. Tick 2: writer
        # reports no change. 1 main rule file + one sidecar per
        # HASH_TYPES entry per tick.
        n_writes_per_tick = 1 + len(HASH_TYPES)
        write_fn = MagicMock(
            side_effect=[True] * n_writes_per_tick
            + [False] * n_writes_per_tick
        )

        runner = SyncRunner(
            cfg, client=client, reloader=reloader, write_fn=write_fn
        )
        runner.run_once()
        assert runner.reload_pending is True
        runner.run_once()
        assert runner.reload_pending is False
        assert reloader.reload_rules.call_count == 2

    def test_hash_list_files_written_before_main_rule_file(
        self, tmp_path: Path
    ):
        """Suricata's rule file references hash list files; the lists must be
        in place before the rule file is replaced or Suricata could read a
        rule pointing at a stale or missing list. The DI'd write_fn lets us
        capture every write in a single ordered list."""
        from aptl.services.misp_suricata_sync.main import SyncRunner

        cfg = self._cfg(tmp_path)
        attrs = [
            type("A", (), dict(type="sha256", value="a" * 64, event_id=None))(),
        ]
        client = MagicMock()
        client.fetch_tagged_attributes.return_value = attrs

        write_order: list[str] = []

        def write_fn(target: Path, content: str) -> bool:
            write_order.append(str(target))
            return True

        reloader = MagicMock()
        reloader.reload_rules.return_value = True

        SyncRunner(
            cfg, client=client, reloader=reloader, write_fn=write_fn
        ).run_once()

        # Both the sidecar list and the rule file got written.
        assert any("misp-sha256.list" in p for p in write_order), write_order
        assert str(cfg.rules_out_path) in write_order
        # And — the invariant — the list precedes the rule file.
        list_idx = next(
            i for i, p in enumerate(write_order) if "misp-sha256.list" in p
        )
        rule_idx = write_order.index(str(cfg.rules_out_path))
        assert list_idx < rule_idx, write_order

    def test_run_loop_exits_when_stop_event_set(self, tmp_path: Path, mocker):
        from aptl.services.misp_suricata_sync.main import run_loop

        cfg = self._cfg(tmp_path)
        stop = threading.Event()
        stop.set()  # exit before first iteration

        client = MagicMock()
        client.wait_for_ready.return_value = True
        reloader = MagicMock()

        run_loop(cfg, stop=stop, client=client, reloader=reloader)
        client.fetch_tagged_attributes.assert_not_called()

    def test_main_fails_fast_on_missing_api_key(self, monkeypatch):
        from aptl.services.misp_suricata_sync.main import main

        monkeypatch.delenv("MISP_API_KEY", raising=False)
        rc = main()
        assert rc != 0
