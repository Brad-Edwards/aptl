"""Service entrypoint: poll MISP, render rules, reload Suricata.

The loop is split into a pure :func:`run_once` that processes a single tick
plus a :func:`run_loop` that schedules ticks against a stop event. Both
accept already-constructed collaborators so they can be unit-tested without
real MISP, sockets, or filesystem.
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


def run_once(
    cfg: ServiceConfig,
    *,
    client: MispClient,
    writer: RuleFileWriter,
    reloader: SuricataReloader,
) -> None:
    """Execute one sync tick. Tolerates MISP and reloader failures."""
    attrs = client.fetch_tagged_attributes()
    if attrs is None:
        log.warning(
            "MISP fetch failed; preserving existing %s",
            cfg.rules_out_path,
        )
        return

    translator = IocTranslator(
        sid_base=cfg.sid_base,
        rules_out_dir=str(cfg.rules_out_path.parent),
    )
    result = translator.translate(attrs)
    rules_text = render_rules_file(
        result.rules,
        misp_url=cfg.misp_url,
        tag_filter=cfg.ioc_tag_filter,
        sid_base=cfg.sid_base,
    )

    changed = writer.write_if_changed(rules_text)

    # Mirror each non-empty hash bucket to its sidecar list file. Each list
    # uses its own writer instance so the atomic-rename contract still holds
    # per file.
    for hash_type, digests in result.hash_lists.items():
        list_path = _hash_list_path(cfg.rules_out_path, hash_type)
        list_writer = RuleFileWriter(list_path)
        if list_writer.write_if_changed(render_hash_list_file(hash_type, digests)):
            changed = True

    if not changed:
        log.debug("No rule changes; skipping reload")
        return

    log.info(
        "Wrote %d rules (+ %d hash-type sidecars) to %s; triggering Suricata reload",
        len(result.rules),
        len(result.hash_lists),
        cfg.rules_out_path,
    )
    reloader.reload_rules()


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

    while not stop.is_set():
        run_once(cfg, client=client, writer=writer, reloader=reloader)
        stop.wait(cfg.sync_interval_seconds)


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
