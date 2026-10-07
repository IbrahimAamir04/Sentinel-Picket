from django.db.models import Case, IntegerField, Value, When
from rest_framework import viewsets

from core.filters import DeterministicOrderMixin

from .filters import AlertFilter
from .models import Alert, Severity
from .serializers import AlertSerializer

SEVERITY_RANK = Case(
    When(severity=Severity.CRITICAL, then=Value(4)),
    When(severity=Severity.HIGH, then=Value(3)),
    When(severity=Severity.MEDIUM, then=Value(2)),
    default=Value(1),
    output_field=IntegerField(),
)


class AlertViewSet(DeterministicOrderMixin, viewsets.ReadOnlyModelViewSet):
    """Read-only. Alerts only enter the system through the ingestion layer (Phase 3)."""

    serializer_class = AlertSerializer
    filterset_class = AlertFilter
    default_ordering = "-timestamp"

    def get_queryset(self):
        return Alert.objects.select_related("sensor").annotate(severity_rank=SEVERITY_RANK)
