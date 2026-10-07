"""Builds a deterministic synthetic dataset. Never imported by production code paths."""
import random
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from alerts.models import Alert
from payloads.models import Payload
from sensors.models import Sensor

from .templates import EXTERNAL_PREFIXES, FILE_TYPES, OUTBOUND_SIDS, RULES, SENSORS

SPAN_DAYS = 14
ALERT_COUNT = 720
PAYLOAD_COUNT = 72


def weighted(rng, items):
    return rng.choices([i for i, _ in items], weights=[w for _, w in items])[0]


@transaction.atomic
def generate(seed: int = 20261002, now=None) -> dict:
    rng = random.Random(seed)
    now = now or timezone.now()
    sensors = []
    for name, host, os_, ip, ver, _w, hb in SENSORS:
        last = now - timedelta(seconds=3) if hb == "live" else now - timedelta(seconds=hb)
        sensors.append(Sensor.objects.create(name=name, hostname=host, os=os_, ip=ip, snort_version=ver, last_seen=last))
    sweights = [(i, s[5]) for i, s in enumerate(SENSORS)]

    def ext():
        return f"{rng.choice(EXTERNAL_PREFIXES)}.{rng.randint(2, 253)}"

    def internal(i):
        return ".".join(SENSORS[i][3].split(".")[:3]) + f".{rng.randint(30, 220)}"

    payload_rules = [r for r in RULES if r[8]]
    status_dist = [("MALICIOUS", 36), ("CLEAN", 20), ("UNKNOWN", 22), ("SUSPICIOUS", 16), ("ERROR", 6)]
    payloads, seen = [], set()
    for _ in range(PAYLOAD_COUNT):
        sha = "%064x" % rng.getrandbits(256)
        while sha in seen:
            sha = "%064x" % rng.getrandbits(256)
        seen.add(sha)
        rule = rng.choices(payload_rules, weights=[r[7] for r in payload_rules])[0]
        si = weighted(rng, sweights)
        mime, ext_, names, lo, hi = rng.choice(FILE_TYPES)
        first = now - timedelta(days=(rng.random() ** 1.6) * (SPAN_DAYS - 0.2), minutes=20)
        last = min(now - timedelta(seconds=30), first + timedelta(days=rng.random() * 3))
        status = weighted(rng, status_dist)
        total = rng.randint(68, 74)
        mal = sus = und = tot = checked = None
        if status == "MALICIOUS":
            mal, sus = rng.randint(14, 58), rng.randint(0, 6)
        elif status == "SUSPICIOUS":
            mal, sus = rng.randint(0, 3), rng.randint(3, 9)
        elif status == "CLEAN":
            mal, sus = 0, 0
        if mal is not None:
            tot, und = total, total - mal - sus
            checked = min(now - timedelta(minutes=1), first + timedelta(minutes=rng.randint(2, 240)))
        payloads.append(Payload(
            sha256=sha, sensor=sensors[si], first_seen=first, last_seen=last, size=rng.randint(lo, hi),
            mime_type=mime, filename=f"{rng.choice(names)}.{ext_}" if rng.random() < 0.7 else None,
            signature_id=rule[0], signature=rule[1], status=status, vt_malicious=mal, vt_suspicious=sus,
            vt_undetected=und, vt_total=tot, vt_last_checked=checked,
        ))
    Payload.objects.bulk_create(payloads)

    def build(si, ts, rule, payload=None, with_payload=True):
        sid, msg, cls, prio, sev, proto, ports, _w, _p = rule
        outbound = sid in OUTBOUND_SIDS
        dport = rng.choice(ports) if ports else None
        eph = None if proto == "ICMP" else rng.randint(1025, 65535)
        a, b = internal(si), ext()
        has = payload is not None and with_payload
        return Alert(
            sensor=sensors[si], timestamp=ts, signature_id=sid, signature=msg, classification=cls, priority=prio,
            severity=sev, protocol=proto, source_ip=a if outbound else b, source_port=eph,
            destination_ip=b if outbound else a, destination_port=dport, payload_available=has,
            payload_hash=payload.sha256 if has else None, payload_size=payload.size if has else None,
            raw_event={"demo": True},
        )

    by_sid = {r[0]: r for r in RULES}
    alerts = []
    for p in payloads:
        alerts.append(build(sensors.index(p.sensor), p.first_seen + timedelta(seconds=10), by_sid[p.signature_id], p))
    fill = [(r, r[7]) for r in RULES]
    while len(alerts) < ALERT_COUNT:
        r = weighted(rng, fill)
        if r[8]:
            p = rng.choice([x for x in payloads if x.signature_id == r[0]])
            span = max((p.last_seen - p.first_seen).total_seconds(), 60)
            ts = min(p.first_seen + timedelta(seconds=rng.random() * span), now - timedelta(seconds=5))
            alerts.append(build(sensors.index(p.sensor), ts, r, p, rng.random() > 0.18))
        else:
            ts = now - timedelta(days=(rng.random() ** 1.35) * SPAN_DAYS)
            alerts.append(build(weighted(rng, sweights), ts, r))
    Alert.objects.bulk_create(alerts)
    return {"sensors": len(sensors), "payloads": len(payloads), "alerts": len(alerts)}
