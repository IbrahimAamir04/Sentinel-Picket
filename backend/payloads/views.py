from datetime import datetime, time, timedelta

from django.db.models import Count, F, IntegerField, OuterRef, Subquery, Value
from django.db.models.functions import Coalesce, TruncDay
from django.utils import timezone
from rest_framework import status as http
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle, UserRateThrottle
from rest_framework import viewsets

from accounts.permissions import IsAnalyst
from alerts.models import Alert
from core.filters import DeterministicOrderMixin
from core.timeutils import parse_tz

from .filters import PayloadFilter
from .models import Payload, PayloadStatus
from .serializers import PayloadSerializer

TREND_DAYS = 14
SHA256_REGEX = "[0-9a-fA-F]{64}"


class PayloadViewSet(DeterministicOrderMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = PayloadSerializer
    filterset_class = PayloadFilter
    lookup_field = "sha256"
    lookup_value_regex = SHA256_REGEX
    default_ordering = "-first_seen"
    throttle_scope = None  # set per action (rescan)

    def get_queryset(self):
        alert_count = (
            Alert.objects.filter(payload_hash=OuterRef("sha256"))
            .order_by().values("payload_hash").annotate(c=Count("id")).values("c")
        )
        return (
            Payload.objects.select_related("sensor")
            .annotate(
                alert_count=Coalesce(Subquery(alert_count, output_field=IntegerField()), Value(0)),
                vt_detection=Coalesce(F("vt_malicious"), Value(-1)),
            )
        )

    def get_object(self):
        self.kwargs[self.lookup_field] = self.kwargs[self.lookup_field].lower()
        return super().get_object()

    @action(detail=False, methods=["get"], pagination_class=None, filterset_class=None)
    def summary(self, request):
        counts = dict(Payload.objects.values_list("status").annotate(n=Count("pk")))
        out = {s.value: counts.get(s.value, 0) for s in PayloadStatus}
        out["total"] = sum(out.values())
        return Response(out)

    @action(detail=False, methods=["get"], pagination_class=None, filterset_class=None)
    def trend(self, request):
        tz = parse_tz(request)
        today = timezone.now().astimezone(tz).date()
        # Midnights are rebuilt from calendar dates, so DST changes cannot shift a bucket.
        days = [
            datetime.combine(today - timedelta(days=TREND_DAYS - 1 - i), time.min, tzinfo=tz) for i in range(TREND_DAYS)
        ]
        start = days[0]
        rows = (
            Payload.objects.filter(first_seen__gte=start)
            .annotate(day=TruncDay("first_seen", tzinfo=tz))
            .values("day", "status").annotate(n=Count("pk"))
        )
        index = {d.date(): {"MALICIOUS": 0, "SUSPICIOUS": 0, "CLEAN": 0, "UNKNOWN": 0} for d in days}
        for r in rows:
            bucket = index.get(r["day"].astimezone(tz).date())
            if bucket is not None:
                bucket["UNKNOWN" if r["status"] == PayloadStatus.ERROR else r["status"]] += r["n"]
        return Response([{"day": d.isoformat(), **index[d.date()]} for d in days])

    @action(detail=True, methods=["get"], url_path="virustotal", pagination_class=None, filterset_class=None)
    def virustotal(self, request, sha256=None):
        """Cached result only. This endpoint never contacts VirusTotal."""
        p = self.get_object()
        return Response(
            {
                "sha256": p.sha256,
                "status": p.status,
                "lookup_performed": p.vt_last_checked is not None,
                "malicious": p.vt_malicious,
                "suspicious": p.vt_suspicious,
                "undetected": p.vt_undetected,
                "total": p.vt_total,
                "last_checked": p.vt_last_checked,
                "submitted_at": p.vt_submitted_at,
                "source": "local-cache",
            }
        )

    @action(detail=True, methods=["post"], url_path="rescan", permission_classes=[IsAnalyst],
            throttle_classes=[UserRateThrottle, ScopedRateThrottle], throttle_scope="rescan", pagination_class=None, filterset_class=None)
    def rescan(self, request, sha256=None):
        if not Payload.objects.filter(pk=sha256.lower()).exists():
            raise NotFound("Payload not found.")
        return Response(
            {"detail": "VirusTotal integration is not enabled on this server yet. It arrives in Phase 4."},
            status=http.HTTP_501_NOT_IMPLEMENTED,
        )
