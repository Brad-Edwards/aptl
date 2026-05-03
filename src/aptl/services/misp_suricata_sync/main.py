"""Service entrypoint: poll MISP, render rules, reload Suricata.

The loop is split into a stateful :class:`SyncRunner` that processes ticks
plus a :func:`run_loop` that drives it against a stop event. Both accept
already-constructed collaborators so they can be unit-tested without real
MISP, sockets, or filesystem.
"""

from __future__ import annotations

import logging
import signal
import threading
from pathlib import Path

from aptl.services.misp_suricata_sync.config import ServiceConfig
from aptl.services.misp_suricata_sync.misp_client import MispClient
from aptl.services.misp_suricata_sync.rule_writer import RuleFileWriter
from aptl.services.misp_suricata_sync.suricata_reloader import SuricataReloader
from aptl.services.misp_suricata_sync.translator import (
    IocTranslator,
    render_hash_list_file,
    render_rules_file,
)
from aptl.utils.logging import get_logger, setup_logging

log = get_logger("misp_suricata_sync")

_READY_TIMEOUT_SECONDS = 10


def _hash_list_path(rules_out_path: Path, hash_type: str) -> Path:
    return rules_out_path.parent / f"misp-{hash_type}.list"


class SyncRunner:
    """One sync tick at a time, with reload-retry state across ticks."""

    def __init__(
        self,
        cfg: ServiceConfig,
        *,
        client: MispClient,
        writer: RuleFileWriter,
        reloader: SuricataReloader,
    ) -> None:
        self._cfg = cfg
        self._client = client
        self._writer = writer
        self._reloader = reloader
        self._reload_pending = False

    @property
    def reload_pending(self) -> bool:
        return self._reload_pending

    def run_once(self) -> None:
        """Execute one sync tick. Tolerates MISP and reloader failures."""
        attrs = self._client.fetch_tagged_attributes()
        if attrs is None:
            log.warning(
                "MISP fetch failed or returned malformed envelope; preserving "
                "existing %s",
                self._cfg.rules_out_path,
            )
            return

        translator = IocTranslator(
            sid_base=self._cfg.sid_base,
            rules_out_dir=str(self._cfg.rules_out_path.parent),
        )
        result = translator.translate(attrs)
        rules_text = render_rules_file(
            result.rules,
            misp_url=self._cfg.misp_url,
            tag_filter=self._cfg.ioc_tag_filter,
            sid_base=self._cfg.sid_base,
        )

        # Order matters: write each per-type hash list BEFORE the rule file
        # that references it, so Suricata never reads a rule pointing at a
        # stale or missing list.
        any_changed = False
        for hash_type, digests in result.hash_lists.items():
            list_path = _hash_list_path(self._cfg.rules_out_path, hash_type)
            list_writer = RuleFileWriter(list_path)
            if list_writer.write_if_changed(
                render_hash_list_file(hash_type, digests)
            ):
                any_changed = True

        if self._writer.write_if_changed(rules_text):
            any_changed = True

        if not (any_changed or self._reload_pending):
            log.debug("No rule changes; skipping reload")
            return

        if self._reload_pending and not any_changed:
            log.info("Retrying Suricata reload after prior failure")

        log.info(
            "Wrote %d rules (+ %d hash-type sidecars) to %s; triggering Suricata reload",
            len(result.rules),
            len(result.hash_lists),
            self._cfg.rules_out_path,
        )
        ok = self._reloader.reload_rules()
        self._reload_pending = not ok


def run_loop(
    cfg: ServiceConfig,
    *,
    stop: threading.Event,
    client: MispClient,
    writer: RuleFileWriter,
    reloader: SuricataReloader,
) -> None:
    """Block until ``stop`` is set, executing one tick per interval."""
    while not stop.is_set():
        if client.wait_for_ready(timeout=_READY_TIMEOUT_SECONDS):
            break
        log.info("Waiting for MISP to become reachable...")

    runner = SyncRunner(cfg, client=client, writer=writer, reloader=reloader)
    while not stop.is_set():
        runner.run_once()
        stop.wait(cfg.sync_interval_seconds)


# Backwards-compatible function entry point used by tests that don't need
# multi-tick state. Each call constructs a fresh :class:`SyncRunner`, so
# reload-retry is a no-op in the function form.
def run_once(
    cfg: ServiceConfig,
    *,
    client: MispClient,
    writer: RuleFileWriter,
    reloader: SuricataReloader,
) -> None:
    SyncRunner(
        cfg, client=client, writer=writer, reloader=reloader
    ).run_once()


def main() -> int:
    setup_logging(level=logging.INFO)
    try:
        cfg = ServiceConfig.from_env()
    except Exception as exc:  # noqa: BLE001 - explicit fail-fast on bad env
        log.error("misp-suricata-sync failed to start: %s", exc)
        return 2

    setup_logging(level=getattr(logging, cfg.log_level.upper(), logging.INFO))
    log.info(
        "misp-suricata-sync starting; "
        "misp_url=%s tag_filter=%s sync_interval=%ds rules_out=%s",
        cfg.misp_url,
        cfg.ioc_tag_filter,
        cfg.sync_interval_seconds,
        cfg.rules_out_path,
    )

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    client = MispClient(cfg)
    writer = RuleFileWriter(cfg.rules_out_path)
    reloader = SuricataReloader(cfg.suricata_socket_path)

    run_loop(cfg, stop=stop, client=client, writer=writer, reloader=reloader)
    log.info("misp-suricata-sync exiting cleanly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
