from django.db.models import Q
from django_filters import rest_framework as filters

from .models import Alert, Severity

SEARCH_MAX = 100


class AlertFilter(filters.FilterSet):
    severity = filters.ChoiceFilter(choices=Severity.choices)
    sensor = filters.NumberFilter(field_name="sensor_id")
    protocol = filters.CharFilter(field_name="protocol", lookup_expr="iexact")
    rule = filters.NumberFilter(field_name="signature_id")
    has_payload = filters.BooleanFilter(field_name="payload_available")
    date_from = filters.IsoDateTimeFilter(field_name="timestamp", lookup_expr="gte")
    date_to = filters.IsoDateTimeFilter(field_name="timestamp", lookup_expr="lte")
    search = filters.CharFilter(method="search_filter")
    ordering = filters.OrderingFilter(
        fields=(
            ("timestamp", "timestamp"),
            ("severity_rank", "severity"),
            ("signature", "signature"),
            ("classification", "classification"),
            ("source_ip", "source_ip"),
            ("destination_ip", "destination_ip"),
            ("protocol", "protocol"),
            ("sensor__name", "sensor"),
            ("payload_available", "payload"),
        )
    )

    class Meta:
        model = Alert
        fields: list[str] = []

    def search_filter(self, queryset, name, value):
        term = value.strip()[:SEARCH_MAX]
        if not term:
            return queryset
        q = (
            Q(signature__icontains=term)
            | Q(classification__icontains=term)
            | Q(protocol__icontains=term)
            | Q(sensor__name__icontains=term)
            | Q(payload_hash__icontains=term)
            | Q(source_ip__icontains=term)
            | Q(destination_ip__icontains=term)
        )
        if term.isdigit():
            q |= Q(signature_id=int(term))
        return queryset.filter(q)
