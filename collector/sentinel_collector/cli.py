from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
from pathlib import Path

from . import __version__, snort
from .client import Client, TransientError, classify
from .config import Config, ConfigError, load
from .runner import Runner, chunks
from .state import StateStore
from .tailer import Tailer


def _setup_logging(level: str) -> None:
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s %(message)s", stream=sys.stderr)


def _with_payloads(cfg: Config, enabled: bool) -> Config:
    from dataclasses import replace

    return replace(cfg, payloads_enabled=True) if enabled else cfg


def cmd_run(cfg: Config, _args) -> int:
    stop = threading.Event()
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):  # SIGBREAK exists on Windows only
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), lambda *_: stop.set())
    state = StateStore(cfg.state_file, cfg.alert_file)
    tailer = Tailer(cfg.alert_file, cfg.start_at, cfg.max_line_bytes, state.load())
    Runner(cfg, Client(cfg), tailer, state, stop).run_forever()
    return 0


def cmd_check(cfg: Config, _args) -> int:
    ok = True
    p = Path(cfg.alert_file)
    if p.is_file():
        print(f"OK    alert file readable: {p} ({p.stat().st_size} bytes)")
    else:
        print(f"WARN  alert file not found yet: {p} (fine if Snort has not started)")
    try:
        Path(cfg.state_file).parent.mkdir(parents=True, exist_ok=True)
        print(f"OK    state directory: {Path(cfg.state_file).parent}")
    except OSError as e:
        ok = False
        print(f"FAIL  cannot create state directory: {e.strerror}")
    runner = Runner(cfg, Client(cfg), Tailer(cfg.alert_file, "end", cfg.max_line_bytes), None)
    try:
        resp = runner.client.heartbeat({"collector_version": __version__})
    except TransientError as e:
        print(f"FAIL  cannot reach {cfg.url}: {e}")
        return 1
    kind = classify(resp.status)
    if kind == "ok":
        print(f"OK    server reachable and API key accepted ({cfg.url})")
    elif kind == "auth":
        ok = False
        print(f"FAIL  server rejected the API key (HTTP {resp.status}). Check it, or whether the sensor was disabled or its key rotated.")
    else:
        ok = False
        print(f"FAIL  server answered HTTP {resp.status}: {resp.body.get('detail', '')}")
    return 0 if ok else 1


def cmd_dry_run(cfg: Config, args) -> int:
    """Parse a file and print what would be sent. No network, no state."""
    cfg = _with_payloads(cfg, args.payloads)
    runner = Runner(cfg, None, None, None)  # type: ignore[arg-type]
    lines = [ln.strip() for ln in Path(args.file).read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
    events = runner.parse(lines)
    for e in events:
        print(json.dumps(e, separators=(",", ":")))
    print(f"# {len(events)} event(s) would be sent, {runner.stats['skipped']} line(s) skipped", file=sys.stderr)
    return 0


def cmd_replay(cfg: Config, args) -> int:
    """Send a file once from the start, ignoring saved state. For testing; remember the data lands in the real database."""
    cfg = _with_payloads(cfg, args.payloads)
    print(f"Sending {args.file} to {cfg.url}. Use only a test server: these events become real rows.", file=sys.stderr)
    runner = Runner(cfg, Client(cfg), None, None)  # type: ignore[arg-type]
    lines = [ln.strip() for ln in Path(args.file).read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
    events = runner.parse(lines)
    runner.heartbeat()
    try:
        for group in chunks(events, cfg.batch_size):
            runner.deliver(group)
    except KeyboardInterrupt:
        return 130
    s = runner.stats
    print(f"accepted={s['accepted']} duplicates={s['duplicates']} rejected={s['rejected']} dropped={s['dropped']} skipped={s['skipped']}")
    return 0 if not (s["dropped"] or s["rejected"]) else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel_collector", description="Ships Snort 2 alert_fast or Snort 3 JSON alerts to Sentinel.")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name, helptext in (("run", "follow the alert file and send new alerts (the normal mode)"),
                           ("check", "validate the config and test the connection and API key"),
                           ("dry-run", "parse a file and print the events that would be sent (no network)"),
                           ("replay", "send a whole file once, for testing")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("--config", "-c", required=True, help="path to collector.toml")
        if name in ("dry-run", "replay"):
            p.add_argument("--file", "-f", required=True, help="a file of Snort alert_fast or alert_json lines")
            p.add_argument("--payloads", action="store_true", help="hash b64_data even if disabled in the config")
    args = parser.parse_args(argv)

    try:
        cfg = load(args.config)
    except ConfigError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return 2
    _setup_logging(cfg.log_level)
    return {"run": cmd_run, "check": cmd_check, "dry-run": cmd_dry_run, "replay": cmd_replay}[args.command](cfg, args)
