"""All dashboard numbers are computed from database rows. Nothing here is hardcoded or cached by hand."""
from datetime import datetime, time, timedelta, timezone as dt_timezone

from django.db.models import Count, Max, Q
from django.db.models.functions import TruncDay, TruncHour
from django.utils import timezone

from alerts.models import Alert, Severity
from payloads.models import Payload, PayloadStatus


def stats() -> dict:
    sev = Alert.objects.aggregate(
        total=Count("id"),
        **{s.value: Count("id", filter=Q(severity=s.value)) for s in Severity},
    )
    pay = Payload.objects.aggregate(
        total=Count("pk"),
        malicious=Count("pk", filter=Q(status=PayloadStatus.MALICIOUS)),
        checked=Count("pk", filter=Q(vt_total__isnull=False)),
    )
    classifications = (
        Alert.objects.exclude(classification="")
        .values("classification").annotate(count=Count("id")).order_by("-count", "classification")
    )
    return {
        "total_alerts": sev["total"],
        "by_severity": {s.value: sev[s.value] for s in Severity},
        "total_payloads": pay["total"],
        "malicious_payloads": pay["malicious"],
        "checked_payloads": pay["checked"],
        # Malicious payloads divided by payloads that actually have a VirusTotal result.
        "detection_rate": (pay["malicious"] / pay["checked"]) if pay["checked"] else 0,
        "classifications": [{"name": c["classification"], "count": c["count"]} for c in classifications],
    }


def timeline(range_key: str, tz) -> list[dict]:
    now = timezone.now().astimezone(tz)
    if range_key == "24h":
        end = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        end_utc = end.astimezone(dt_timezone.utc)
        starts = [end_utc - timedelta(hours=24 - i) for i in range(24)]
        trunc = TruncHour("timestamp", tzinfo=dt_timezone.utc)
    else:
        today = now.date()
        starts = [
            datetime.combine(today - timedelta(days=6 - i), time.min, tzinfo=tz).astimezone(dt_timezone.utc)
            for i in range(7)
        ]
        end_utc = datetime.combine(today + timedelta(days=1), time.min, tzinfo=tz).astimezone(dt_timezone.utc)
        trunc = TruncDay("timestamp", tzinfo=tz)

    rows = (
        Alert.objects.filter(timestamp__gte=starts[0], timestamp__lt=end_utc)
        .annotate(bucket=trunc).values("bucket", "severity").annotate(n=Count("id"))
    )
    points = {int(s.timestamp()): {"bucket": s.isoformat(), **{v.value: 0 for v in Severity}} for s in starts}
    for r in rows:
        point = points.get(int(r["bucket"].timestamp()))
        if point is not None:
            point[r["severity"]] += r["n"]
    return list(points.values())


def protocols() -> list[dict]:
    rows = Alert.objects.exclude(protocol="").values("protocol").annotate(count=Count("id")).order_by("-count", "protocol")
    return [{"protocol": r["protocol"], "count": r["count"]} for r in rows]


def top_rules(limit: int) -> list[dict]:
    rows = (
        Alert.objects.values("signature_id")
        .annotate(signature=Max("signature"), classification=Max("classification"), count=Count("id"))
        .order_by("-count", "signature_id")[:limit]
    )
    return list(rows)
