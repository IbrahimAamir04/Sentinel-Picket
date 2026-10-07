"""Turns validated events into alerts and payload metadata. No file or packet content ever reaches this layer."""
import hashlib
import json
import logging
from dataclasses import dataclass, field

from django.conf import settings
from django.db import transaction

from alerts.models import Alert
from payloads.models import Payload

from .severity import derive_severity

log = logging.getLogger("sentinel.ingestion")


@dataclass
class IngestResult:
    accepted: int = 0
    duplicates: int = 0
    rejected: list[dict] = field(default_factory=list)  # [{"index": i, "errors": {...}}]


def event_id(e: dict) -> str:
    """Same event in, same id out. This is what makes a collector retry harmless."""
    identity = [
        e["timestamp"].isoformat(), e["signature_id"], e.get("gid"), e.get("rev"), e.get("protocol", ""),
        e.get("source_ip"), e.get("source_port"), e.get("destination_ip"), e.get("destination_port"), e.get("pkt_num"),
    ]
    return hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()


def _bounded_raw(raw: dict) -> dict:
    encoded = json.dumps(raw, separators=(",", ":"), default=str)
    if len(encoded.encode()) > settings.INGEST_MAX_RAW_BYTES:
        return {"truncated": True, "reason": f"original event exceeded {settings.INGEST_MAX_RAW_BYTES} bytes"}
    return json.loads(encoded)


def ingest(sensor, items: list[tuple[int, dict]]) -> IngestResult:
    """`items` is [(index in the request, validated event)]. Valid events are stored even if others in the batch are rejected."""
    result = IngestResult()
    if not items:
        return result

    with transaction.atomic():
        ids = {i: event_id(e) for i, e in items}
        existing_ids = set(Alert.objects.filter(sensor=sensor, event_id__in=set(ids.values())).values_list("event_id", flat=True))

        shas = {e["payload"]["sha256"] for _, e in items if e.get("payload")}
        known = {p.sha256: p for p in Payload.objects.select_for_update().filter(sha256__in=shas)} if shas else {}

        seen_ids: set[str] = set()
        batch_sizes: dict[str, int] = {}
        observed: dict[str, dict] = {}
        alerts: list[Alert] = []

        for index, e in items:
            eid = ids[index]
            if eid in existing_ids or eid in seen_ids:
                result.duplicates += 1
                continue

            meta = e.get("payload")
            if meta:
                sha, size = meta["sha256"], meta["size"]
                expected = known[sha].size if sha in known else batch_sizes.get(sha)
                if expected is not None and expected != size:
                    # Same SHA-256, different size: impossible for genuine data. Refuse rather than corrupt the record.
                    result.rejected.append({"index": index, "errors": {"payload": ["Size conflicts with the existing record for this SHA-256."]}})
                    continue
                batch_sizes[sha] = size
                obs = observed.setdefault(sha, {"first": e["timestamp"], "last": e["timestamp"], "mime": "", "filename": "", "event": e})
                if e["timestamp"] < obs["first"]:
                    obs["first"], obs["event"] = e["timestamp"], e
                obs["last"] = max(obs["last"], e["timestamp"])
                obs["mime"] = obs["mime"] or meta.get("mime_type") or ""
                obs["filename"] = obs["filename"] or meta.get("filename") or ""

            seen_ids.add(eid)
            alerts.append(Alert(
                sensor=sensor, event_id=eid, timestamp=e["timestamp"], signature_id=e["signature_id"], signature=e["signature"],
                classification=e["classification"], priority=e.get("priority"),
                severity=derive_severity(e.get("priority"), e["classification"]), protocol=e.get("protocol", ""),
                source_ip=e.get("source_ip"), source_port=e.get("source_port"),
                destination_ip=e.get("destination_ip"), destination_port=e.get("destination_port"),
                payload_available=bool(meta), payload_hash=meta["sha256"] if meta else None,
                payload_size=meta["size"] if meta else None, raw_event=_bounded_raw(e.get("raw") or {}),
            ))

        _upsert_payloads(sensor, observed, known, batch_sizes)
        Alert.objects.bulk_create(alerts, ignore_conflicts=True)  # a concurrent duplicate is skipped, not an error
        result.accepted = len(alerts)
    return result


def _upsert_payloads(sensor, observed, known, sizes):
    new, changed = [], []
    for sha, obs in observed.items():
        if sha in known:
            p = known[sha]
            p.first_seen, p.last_seen = min(p.first_seen, obs["first"]), max(p.last_seen, obs["last"])
            p.mime_type = p.mime_type or obs["mime"]
            p.filename = p.filename or obs["filename"] or None
            changed.append(p)
        else:
            ev = obs["event"]
            new.append(Payload(
                sha256=sha, sensor=sensor, first_seen=obs["first"], last_seen=obs["last"], size=sizes[sha],
                mime_type=obs["mime"], filename=obs["filename"] or None,
                signature_id=ev["signature_id"], signature=ev["signature"],
            ))
    if new:
        Payload.objects.bulk_create(new, ignore_conflicts=True)
    if changed:
        Payload.objects.bulk_update(changed, ["first_seen", "last_seen", "mime_type", "filename", "updated_at"])
