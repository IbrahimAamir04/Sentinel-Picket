"""Parse and normalise Snort 3 alert_json and Snort 2 alert_fast records."""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from . import payload as payload_mod

MAX_RAW_BYTES = 8192
SNORT2_FAST_RE = re.compile(
    r"^(?P<timestamp>\d{2}/\d{2}(?:/\d{2})?-\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<msg>.*?)\s+\[\*\*\]"
    r"(?:\s+\[Classification:\s*(?P<class>.*?)\])?"
    r"(?:\s+\[Priority:\s*(?P<priority>\d+)\])?"
    r"\s+\{(?P<proto>[^}]+)\}\s+(?P<src_ap>\S+)\s+->\s+(?P<dst_ap>\S+)\s*$"
)


class SkipEvent(Exception):
    """A line that cannot become an alert. The reason is counted and logged, never fatal."""


def parse_line(line: str) -> dict:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        match = SNORT2_FAST_RE.fullmatch(line)
        if match is None:
            raise SkipEvent("not JSON or Snort 2 alert_fast")
        event = match.groupdict()
        event.update({"gid": int(event["gid"]), "sid": int(event["sid"]), "rev": int(event["rev"]),
                      "format": "snort2_alert_fast", "raw_line": line})
        if event["priority"] is not None:
            event["priority"] = int(event["priority"])
        return event
    if not isinstance(obj, dict):
        raise SkipEvent("JSON line is not an object")
    return obj


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_rule(value: Any) -> tuple[int | None, int | None, int | None]:
    """Snort 3 and Snort 2 write rule identifiers as "gid:sid:rev"."""
    if not isinstance(value, str):
        return None, None, None
    parts = value.split(":")
    if len(parts) != 3:
        return None, None, None
    gid, sid, rev = (_int(p) for p in parts)
    return gid, sid, rev


# --- time -------------------------------------------------------------------------------------------------

def _local_tz(name: str):
    if name.lower() == "utc":
        return timezone.utc
    if name.lower() == "local":
        return None  # the system's local zone, resolved per timestamp (handles DST, needs no tz database)
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(name)
    except Exception:
        raise SkipEvent(f"unknown time zone {name!r} (on Windows, IANA names need: pip install tzdata)")


def _to_utc(naive: datetime, tz_name: str) -> datetime:
    tz = _local_tz(tz_name)
    aware = naive.astimezone() if tz is None else naive.replace(tzinfo=tz)
    return aware.astimezone(timezone.utc)


def parse_timestamp(event: dict, tz_name: str, now: datetime | None = None) -> datetime:
    """
    Preference order: `seconds` (epoch, unambiguous) -> `timestamp` text.
    Snort's default text form is "MM/DD-HH:MM:SS.ffffff": no year and no zone, so the sensor's local zone is assumed
    (configurable) and the year is inferred as the most recent one that is not in the future.
    """
    now = now or datetime.now(timezone.utc)
    secs = event.get("seconds")
    if secs is not None and not isinstance(secs, bool):
        try:
            return datetime.fromtimestamp(float(secs), tz=timezone.utc)
        except (TypeError, ValueError, OverflowError, OSError):
            pass  # fall through to the text timestamp

    text = event.get("timestamp")
    if isinstance(text, (int, float)) and not isinstance(text, bool):
        try:
            return datetime.fromtimestamp(float(text), tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            raise SkipEvent("unusable timestamp")
    if not isinstance(text, str) or not text:
        raise SkipEvent("no timestamp")

    for fmt in ("%m/%d/%y-%H:%M:%S.%f", "%m/%d/%y-%H:%M:%S"):  # with a year (older Snort style)
        try:
            return _to_utc(datetime.strptime(text, fmt), tz_name)
        except ValueError:
            continue
    for fmt in ("%m/%d-%H:%M:%S.%f", "%m/%d-%H:%M:%S"):  # Snort 3 default: no year
        try:
            parsed = datetime.strptime(f"2000/{text}", f"%Y/{fmt}")  # 2000 is a leap year, so Feb 29 parses
        except ValueError:
            continue
        local_now = now.astimezone() if _local_tz(tz_name) is None else now.astimezone(_local_tz(tz_name))
        for year in (local_now.year, local_now.year - 1):
            try:
                candidate = _to_utc(parsed.replace(year=year), tz_name)
            except ValueError:  # Feb 29 in a non-leap year
                continue
            if candidate <= now + timedelta(days=1):
                return candidate
        raise SkipEvent("timestamp has no valid year")
    try:  # ISO 8601 as a courtesy
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc) if dt.tzinfo else _to_utc(dt, tz_name)
    except ValueError:
        raise SkipEvent("unrecognised timestamp format")


# --- addresses --------------------------------------------------------------------------------------------

def _ip(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _port(value: Any) -> int | None:
    n = _int(value)
    return n if n is not None and 1 <= n <= 65535 else None  # 0 means "no port" (e.g. ICMP)


def split_ap(value: Any) -> tuple[str | None, int | None]:
    """
    Splits Snort's "address:port" form. IPv4 and bracketed IPv6 are unambiguous. A bare IPv6 string that is itself a
    valid address is treated as an address with no port; if your IPv6 alerts show wrong ports, add src_addr/src_port
    (and dst_addr/dst_port) to the alert_json fields so no splitting is needed.
    """
    if not isinstance(value, str) or not value:
        return None, None
    value = value.strip()
    if value.startswith("["):
        host, _, rest = value[1:].partition("]")
        ip, port = _ip(host), (_port(rest[1:]) if rest.startswith(":") else None)
    elif value.count(":") == 1:
        host, _, port_text = value.partition(":")
        ip, port = _ip(host), _port(port_text)
    elif _ip(value):
        ip, port = _ip(value), None
    else:
        host, _, port_text = value.rpartition(":")
        ip, port = _ip(host), _port(port_text)
    return (ip, port) if ip else (None, None)  # a port with no usable address would only mislead


# --- normalise --------------------------------------------------------------------------------------------

def _cap_raw(event: dict) -> dict:
    raw = {k: v for k, v in event.items() if k != "b64_data"}  # packet bytes stay on the sensor
    if len(json.dumps(raw, separators=(",", ":"), default=str).encode()) > MAX_RAW_BYTES:
        return {"truncated": True}
    return raw


def normalize(event: dict, *, tz_name: str, payloads_enabled: bool, payload_min_bytes: int,
              payload_max_b64_chars: int, now: datetime | None = None) -> dict:
    gid, sid, rev = parse_rule(event.get("rule"))
    sid = _int(event.get("sid")) if event.get("sid") is not None else sid
    gid = _int(event.get("gid")) if event.get("gid") is not None else gid
    rev = _int(event.get("rev")) if event.get("rev") is not None else rev
    if sid is None or sid < 0:
        raise SkipEvent("no rule/sid: not a rule alert")

    ts = parse_timestamp(event, tz_name, now)

    src_ip, src_port = _ip(event.get("src_addr")), _port(event.get("src_port"))
    dst_ip, dst_port = _ip(event.get("dst_addr")), _port(event.get("dst_port"))
    if src_ip is None:
        src_ip, ap_port = split_ap(event.get("src_ap"))
        src_port = src_port or ap_port
    if dst_ip is None:
        dst_ip, ap_port = split_ap(event.get("dst_ap"))
        dst_port = dst_port or ap_port

    proto = event.get("proto")
    out: dict[str, Any] = {
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "signature_id": sid, "gid": gid, "rev": rev,
        "signature": event["msg"] if isinstance(event.get("msg"), str) else None,
        "classification": event["class"] if isinstance(event.get("class"), str) else None,
        "priority": _int(event.get("priority")),
        "protocol": proto.upper() if isinstance(proto, str) and proto else None,
        "source_ip": src_ip, "source_port": src_port, "destination_ip": dst_ip, "destination_port": dst_port,
        "pkt_num": _int(event.get("pkt_num")),
        "raw": _cap_raw(event),
    }
    meta = payload_mod.extract(event.get("b64_data"), payloads_enabled, payload_min_bytes, payload_max_b64_chars)
    if meta:
        out["payload"] = meta
    return {k: v for k, v in out.items() if v is not None}
