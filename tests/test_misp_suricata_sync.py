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
        assert cfg.sid_base == 2_000_000
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

    def test_rejects_interval_below_minimum(self, monkeypatch):
        from aptl.services.misp_suricata_sync.config import ServiceConfig

        monkeypatch.setenv("MISP_API_KEY", "k")
        monkeypatch.setenv("SYNC_INTERVAL_SECONDS", "5")
        with pytest.raises(ValidationError):
            ServiceConfig.from_env()

    def test_rejects_sid_base_outside_range(self, monkeypatch):
        from aptl.services.misp_suricata_sync.config import ServiceConfig

        monkeypatch.setenv("MISP_API_KEY", "k")
        monkeypatch.setenv("SID_BASE", "999")
        with pytest.raises(ValidationError):
            ServiceConfig.from_env()

    def test_accepts_custom_overrides(self, monkeypatch):
        from aptl.services.misp_suricata_sync.config import ServiceConfig

        monkeypatch.setenv("MISP_API_KEY", "k")
        monkeypatch.setenv("MISP_URL", "https://misp.lab")
        monkeypatch.setenv("MISP_VERIFY_SSL", "true")
        monkeypatch.setenv("IOC_TAG_FILTER", "tlp:white")
        monkeypatch.setenv("SYNC_INTERVAL_SECONDS", "60")
        monkeypatch.setenv("SID_BASE", "2500000")
        cfg = ServiceConfig.from_env()
        assert cfg.misp_url == "https://misp.lab"
        assert cfg.misp_verify_ssl is True
        assert cfg.ioc_tag_filter == "tlp:white"
        assert cfg.sync_interval_seconds == 60
        assert cfg.sid_base == 2_500_000


# ---------------------------------------------------------------------------
# Translator
# ---------------------------------------------------------------------------


def _attr(type_: str, value: str, event_id: str | None = None):
    from aptl.services.misp_suricata_sync.models import MispAttribute

    return MispAttribute(type=type_, value=value, event_id=event_id)


class TestTranslator:
    def test_ip_src_emits_alert_ip_rule(self):
        from aptl.services.misp_suricata_sync.translator import IocTranslator

        t = IocTranslator(sid_base=2_000_000)
        rules = t.translate([_attr("ip-src", "198.51.100.42")])
        assert len(rules) == 1
        rule = rules[0].text
        assert rule.startswith("alert ip 198.51.100.42 any -> any any (")
        assert "sid:" in rule
        assert "rev:1" in rule

    def test_ip_dst_emits_alert_ip_rule(self):
        from aptl.services.misp_suricata_sync.translator import IocTranslator

        t = IocTranslator(sid_base=2_000_000)
        rules = t.translate([_attr("ip-dst", "203.0.113.7")])
        assert rules[0].text.startswith("alert ip 203.0.113.7 any -> any any (")

    def test_domain_emits_dns_query_rule(self):
        from aptl.services.misp_suricata_sync.translator import IocTranslator

        t = IocTranslator(sid_base=2_000_000)
        rules = t.translate([_attr("domain", "evil.example.com")])
        rule = rules[0].text
        assert rule.startswith("alert dns any any -> any any (")
        assert "dns.query" in rule
        assert 'content:"evil.example.com"' in rule
        assert "nocase" in rule

    def test_url_emits_http_uri_rule(self):
        from aptl.services.misp_suricata_sync.translator import IocTranslator

        t = IocTranslator(sid_base=2_000_000)
        rules = t.translate([_attr("url", "http://evil.example.com/payload")])
        rule = rules[0].text
        assert rule.startswith("alert http any any -> any any (")
        assert "http.uri" in rule
        assert 'content:"/payload"' in rule

    def test_url_with_only_host_falls_back_to_root_path(self):
        from aptl.services.misp_suricata_sync.translator import IocTranslator

        t = IocTranslator(sid_base=2_000_000)
        rules = t.translate([_attr("url", "http://evil.example.com")])
        assert 'content:"/"' in rules[0].text

    def test_sha256_emits_filesha256_rule(self):
        from aptl.services.misp_suricata_sync.translator import IocTranslator

        h = "a" * 64
        t = IocTranslator(sid_base=2_000_000)
        rules = t.translate([_attr("sha256", h)])
        rule = rules[0].text
        assert rule.startswith("alert http any any -> any any (")
        assert "filesha256" in rule
        assert h in rule

    def test_md5_emits_filemd5_rule(self):
        from aptl.services.misp_suricata_sync.translator import IocTranslator

        h = "b" * 32
        t = IocTranslator(sid_base=2_000_000)
        rules = t.translate([_attr("md5", h)])
        assert "filemd5" in rules[0].text

    def test_sha1_emits_filesha1_rule(self):
        from aptl.services.misp_suricata_sync.translator import IocTranslator

        h = "c" * 40
        t = IocTranslator(sid_base=2_000_000)
        rules = t.translate([_attr("sha1", h)])
        assert "filesha1" in rules[0].text

    def test_unsupported_type_skipped_with_warning(self, caplog):
        from aptl.services.misp_suricata_sync.translator import IocTranslator

        caplog.set_level(logging.WARNING, logger="aptl.misp_suricata_sync")
        t = IocTranslator(sid_base=2_000_000)
        rules = t.translate(
            [
                _attr("regkey", "HKLM\\Software\\Foo"),
                _attr("ip-dst", "198.51.100.1"),
            ]
        )
        assert len(rules) == 1
        assert rules[0].attribute_type == "ip-dst"
        assert any("regkey" in r.message for r in caplog.records)

    def test_action_is_always_alert_never_drop(self):
        """ADR-019 invariant: no drop/reject rules under any input."""
        from aptl.services.misp_suricata_sync.translator import IocTranslator

        t = IocTranslator(sid_base=2_000_000)
        attrs = [
            _attr("ip-src", "1.2.3.4"),
            _attr("ip-dst", "5.6.7.8"),
            _attr("domain", "x.y"),
            _attr("url", "http://x.y/z"),
            _attr("sha256", "d" * 64),
            _attr("md5", "e" * 32),
            _attr("sha1", "f" * 40),
        ]
        rules = t.translate(attrs)
        for r in rules:
            assert r.text.startswith("alert "), r.text
            assert "drop " not in r.text
            assert "reject" not in r.text

    def test_sid_is_deterministic_across_runs(self):
        from aptl.services.misp_suricata_sync.translator import IocTranslator

        t1 = IocTranslator(sid_base=2_000_000)
        t2 = IocTranslator(sid_base=2_000_000)
        a = [_attr("ip-dst", "198.51.100.42")]
        sids1 = [r.sid for r in t1.translate(a)]
        sids2 = [r.sid for r in t2.translate(a)]
        assert sids1 == sids2

    def test_sid_collision_drops_second_with_warning(self, caplog, monkeypatch):
        """When two distinct IOCs hash to the same SID, only one rule emits."""
        from aptl.services.misp_suricata_sync import translator as tmod

        monkeypatch.setattr(tmod, "_crc32_sid_offset", lambda type_, value: 7)
        t = tmod.IocTranslator(sid_base=2_000_000)
        caplog.set_level(logging.WARNING, logger="aptl.misp_suricata_sync")
        rules = t.translate(
            [
                _attr("ip-dst", "198.51.100.1"),
                _attr("ip-dst", "198.51.100.2"),
            ]
        )
        assert len(rules) == 1
        assert any("collision" in r.message.lower() for r in caplog.records)

    def test_output_is_sorted_for_stable_render(self):
        from aptl.services.misp_suricata_sync.translator import IocTranslator

        t = IocTranslator(sid_base=2_000_000)
        attrs_a = [
            _attr("ip-dst", "198.51.100.2"),
            _attr("ip-dst", "198.51.100.1"),
        ]
        attrs_b = list(reversed(attrs_a))
        text_a = [r.text for r in t.translate(attrs_a)]
        text_b = [r.text for r in t.translate(attrs_b)]
        assert text_a == text_b

    def test_escapes_non_alnum_in_content_via_pipe_hex(self):
        from aptl.services.misp_suricata_sync.translator import IocTranslator

        t = IocTranslator(sid_base=2_000_000)
        rules = t.translate([_attr("domain", "ev\"il.example.com")])
        assert '"' not in rules[0].text.split('content:"', 1)[1].split('"', 1)[0]
        assert "|22|" in rules[0].text

    def test_rejects_quote_or_semicolon_in_value_via_escape(self):
        """Even with hostile attribute values, the rule must remain syntactically clean."""
        from aptl.services.misp_suricata_sync.translator import IocTranslator

        t = IocTranslator(sid_base=2_000_000)
        rules = t.translate(
            [
                _attr("domain", 'a"; sid:1; rev:1; reference:foo,bar; msg:"x'),
            ]
        )
        rule = rules[0].text
        # Exactly one trailing semicolon set; only one sid: directive.
        assert rule.count("sid:") == 1
        assert rule.count("msg:") == 1

    def test_event_id_recorded_in_metadata_when_present(self):
        from aptl.services.misp_suricata_sync.translator import IocTranslator

        t = IocTranslator(sid_base=2_000_000)
        rules = t.translate([_attr("ip-dst", "198.51.100.42", event_id="42")])
        assert "metadata:misp_event_id 42" in rules[0].text

    def test_event_id_omitted_when_absent(self):
        from aptl.services.misp_suricata_sync.translator import IocTranslator

        t = IocTranslator(sid_base=2_000_000)
        rules = t.translate([_attr("ip-dst", "198.51.100.42")])
        assert "metadata:" not in rules[0].text


class TestRenderRulesFile:
    def test_header_records_metadata(self):
        from aptl.services.misp_suricata_sync.translator import (
            IocTranslator,
            render_rules_file,
        )

        t = IocTranslator(sid_base=2_000_000)
        rules = t.translate([_attr("ip-dst", "198.51.100.42")])
        text = render_rules_file(
            rules,
            misp_url="https://misp.lab",
            tag_filter="aptl:enforce",
            sid_base=2_000_000,
        )
        assert "# APTL MISP-to-Suricata sync" in text
        assert "https://misp.lab" in text
        assert "aptl:enforce" in text
        assert "ioc_count=1" in text
        assert "alert ip 198.51.100.42" in text

    def test_empty_rules_still_renders_header(self):
        from aptl.services.misp_suricata_sync.translator import render_rules_file

        text = render_rules_file(
            [],
            misp_url="https://misp.lab",
            tag_filter="aptl:enforce",
            sid_base=2_000_000,
        )
        assert "ioc_count=0" in text


# ---------------------------------------------------------------------------
# Rule writer
# ---------------------------------------------------------------------------


class TestRuleFileWriter:
    def test_creates_file_when_missing(self, tmp_path: Path):
        from aptl.services.misp_suricata_sync.rule_writer import RuleFileWriter

        target = tmp_path / "misp-iocs.rules"
        writer = RuleFileWriter(target)
        changed = writer.write_if_changed("hello\n")
        assert changed is True
        assert target.read_text() == "hello\n"

    def test_returns_false_when_content_identical(self, tmp_path: Path):
        from aptl.services.misp_suricata_sync.rule_writer import RuleFileWriter

        target = tmp_path / "misp-iocs.rules"
        target.write_text("same\n")
        writer = RuleFileWriter(target)
        assert writer.write_if_changed("same\n") is False

    def test_returns_true_and_replaces_when_different(self, tmp_path: Path):
        from aptl.services.misp_suricata_sync.rule_writer import RuleFileWriter

        target = tmp_path / "misp-iocs.rules"
        target.write_text("old\n")
        writer = RuleFileWriter(target)
        assert writer.write_if_changed("new\n") is True
        assert target.read_text() == "new\n"

    def test_atomic_write_uses_temp_then_rename(self, tmp_path: Path, mocker):
        from aptl.services.misp_suricata_sync.rule_writer import RuleFileWriter

        target = tmp_path / "misp-iocs.rules"
        target.write_text("old\n")
        spy = mocker.spy(Path, "replace")
        writer = RuleFileWriter(target)
        writer.write_if_changed("new\n")
        assert spy.call_count == 1

    def test_creates_parent_directory_if_missing(self, tmp_path: Path):
        from aptl.services.misp_suricata_sync.rule_writer import RuleFileWriter

        target = tmp_path / "nested" / "misp-iocs.rules"
        writer = RuleFileWriter(target)
        assert writer.write_if_changed("x\n") is True
        assert target.read_text() == "x\n"

    def test_does_not_truncate_when_caller_passes_none(self, tmp_path: Path):
        from aptl.services.misp_suricata_sync.rule_writer import RuleFileWriter

        target = tmp_path / "misp-iocs.rules"
        target.write_text("preserved\n")
        writer = RuleFileWriter(target)
        with pytest.raises(TypeError):
            writer.write_if_changed(None)  # type: ignore[arg-type]
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
            ioc_tag_filter="aptl:enforce",
            sync_interval_seconds=300,
            rules_out_path=Path("/tmp/misp-iocs.rules"),
            suricata_socket_path=Path("/tmp/suricata.sock"),
            sid_base=2_000_000,
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
            ioc_tag_filter="aptl:enforce",
            sync_interval_seconds=300,
            rules_out_path=tmp_path / "misp-iocs.rules",
            suricata_socket_path=tmp_path / "suricata.sock",
            sid_base=2_000_000,
            log_level="INFO",
        )

    def test_skips_write_when_misp_returns_none(self, tmp_path: Path, mocker):
        from aptl.services.misp_suricata_sync.main import run_once

        cfg = self._cfg(tmp_path)
        cfg.rules_out_path.write_text("preserved\n")

        client = MagicMock()
        client.fetch_tagged_attributes.return_value = None
        writer = MagicMock()
        reloader = MagicMock()

        run_once(cfg, client=client, writer=writer, reloader=reloader)

        writer.write_if_changed.assert_not_called()
        reloader.reload_rules.assert_not_called()
        assert cfg.rules_out_path.read_text() == "preserved\n"

    def test_skips_reload_when_writer_reports_no_change(
        self, tmp_path: Path
    ):
        from aptl.services.misp_suricata_sync.main import run_once

        cfg = self._cfg(tmp_path)
        client = MagicMock()
        client.fetch_tagged_attributes.return_value = []
        writer = MagicMock()
        writer.write_if_changed.return_value = False
        reloader = MagicMock()

        run_once(cfg, client=client, writer=writer, reloader=reloader)

        writer.write_if_changed.assert_called_once()
        reloader.reload_rules.assert_not_called()

    def test_triggers_reload_when_writer_reports_change(self, tmp_path: Path):
        from aptl.services.misp_suricata_sync.main import run_once

        cfg = self._cfg(tmp_path)
        client = MagicMock()
        client.fetch_tagged_attributes.return_value = []
        writer = MagicMock()
        writer.write_if_changed.return_value = True
        reloader = MagicMock()

        run_once(cfg, client=client, writer=writer, reloader=reloader)

        reloader.reload_rules.assert_called_once()

    def test_run_loop_exits_when_stop_event_set(self, tmp_path: Path, mocker):
        from aptl.services.misp_suricata_sync.main import run_loop

        cfg = self._cfg(tmp_path)
        stop = threading.Event()
        stop.set()  # exit before first iteration

        client = MagicMock()
        client.wait_for_ready.return_value = True
        writer = MagicMock()
        reloader = MagicMock()

        run_loop(cfg, stop=stop, client=client, writer=writer, reloader=reloader)
        client.fetch_tagged_attributes.assert_not_called()

    def test_main_fails_fast_on_missing_api_key(self, monkeypatch):
        from aptl.services.misp_suricata_sync.main import main

        monkeypatch.delenv("MISP_API_KEY", raising=False)
        rc = main()
        assert rc != 0
