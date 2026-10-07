"""Collector configuration (TOML). The API key is never read from the config file itself."""
from __future__ import annotations

import os
import stat
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

LOOPBACK = {"localhost", "127.0.0.1", "::1"}


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    # server
    url: str
    api_key: str = field(repr=False)  # redacted from repr() and therefore from accidental logging
    allow_insecure_http: bool = False
    ca_file: str = ""
    timeout_seconds: float = 15.0
    # snort
    alert_file: str = ""
    start_at: str = "end"
    timezone: str = "local"
    max_line_bytes: int = 1_048_576
    # payloads
    payloads_enabled: bool = False
    payload_min_bytes: int = 16
    payload_max_b64_chars: int = 1_500_000
    # collector
    state_file: str = ""
    batch_size: int = 100
    flush_interval_seconds: float = 2.0
    heartbeat_interval_seconds: float = 30.0
    log_level: str = "INFO"
    snort_version: str = ""
    sensor_ip: str = ""


def _section(raw: dict, name: str) -> dict:
    value = raw.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"[{name}] must be a table.")
    return value


def _num(section: dict, key: str, default, lo, hi, name: str):
    value = section.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not lo <= value <= hi:
        raise ConfigError(f"{name}.{key} must be a number between {lo} and {hi}.")
    return value


def _resolve_key(server: dict) -> str:
    env_name = server.get("api_key_env", "SENTINEL_API_KEY")
    value = os.environ.get(env_name, "").strip()
    if value:
        return value
    key_file = server.get("api_key_file", "")
    if key_file:
        path = Path(key_file)
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError as e:
            raise ConfigError(f"Cannot read api_key_file {key_file!r}: {e.strerror}.")
        if sys.platform != "win32" and path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            print(f"WARNING: {key_file} is readable by other users. Run: chmod 600 {key_file}", file=sys.stderr)
        if value:
            return value
    raise ConfigError(f"No API key. Set the {env_name} environment variable, or set server.api_key_file to a file containing only the key.")


def load(path: str | Path) -> Config:
    try:
        raw = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"Config file not found: {path}")
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"Config file is not valid TOML: {e}")

    server, snort = _section(raw, "server"), _section(raw, "snort")
    payloads, coll = _section(raw, "payloads"), _section(raw, "collector")

    if "api_key" in server:
        raise ConfigError("Do not put the key in the config file (it gets committed, backed up and read by other users). Use api_key_env or api_key_file.")

    url = str(server.get("url", "")).rstrip("/")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ConfigError("server.url must look like https://sentinel.example.com")
    allow_http = bool(server.get("allow_insecure_http", False))
    if parsed.scheme == "http" and parsed.hostname not in LOOPBACK and not allow_http:
        raise ConfigError("server.url uses plain http, which would send the API key unencrypted. Use https, or set allow_insecure_http = true if you accept that risk.")

    alert_file = str(snort.get("alert_file", ""))
    if not alert_file:
        raise ConfigError("snort.alert_file is required.")
    start_at = snort.get("start_at", "end")
    if start_at not in ("end", "beginning"):
        raise ConfigError('snort.start_at must be "end" or "beginning".')
    state_file = str(coll.get("state_file", ""))
    if not state_file:
        raise ConfigError("collector.state_file is required.")
    tz_name = str(snort.get("timezone", "local"))
    if tz_name.lower() not in ("local", "utc"):
        try:
            from zoneinfo import ZoneInfo

            ZoneInfo(tz_name)
        except Exception:
            raise ConfigError(f"snort.timezone {tz_name!r} is not available. Use \"local\", \"UTC\", or install tzdata (pip install tzdata) for IANA names on Windows.")
    level = str(coll.get("log_level", "INFO")).upper()
    if level not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        raise ConfigError("collector.log_level must be DEBUG, INFO, WARNING or ERROR.")

    return Config(
        url=url, api_key=_resolve_key(server), allow_insecure_http=allow_http, ca_file=str(server.get("ca_file", "")),
        timeout_seconds=_num(server, "timeout_seconds", 15, 1, 120, "server"),
        alert_file=alert_file, start_at=start_at, timezone=tz_name,
        max_line_bytes=int(_num(snort, "max_line_bytes", 1_048_576, 1024, 16_777_216, "snort")),
        payloads_enabled=bool(payloads.get("enabled", False)),
        payload_min_bytes=int(_num(payloads, "min_bytes", 16, 1, 1_000_000, "payloads")),
        payload_max_b64_chars=int(_num(payloads, "max_b64_chars", 1_500_000, 1024, 50_000_000, "payloads")),
        state_file=state_file,
        batch_size=int(_num(coll, "batch_size", 100, 1, 500, "collector")),
        flush_interval_seconds=float(_num(coll, "flush_interval_seconds", 2, 0.1, 300, "collector")),
        heartbeat_interval_seconds=float(_num(coll, "heartbeat_interval_seconds", 30, 5, 3600, "collector")),
        log_level=level, snort_version=str(coll.get("snort_version", "")), sensor_ip=str(coll.get("ip", "")),
    )
