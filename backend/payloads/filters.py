from django.db.models import Q
from django_filters import rest_framework as filters

from .models import Payload, PayloadStatus

SEARCH_MAX = 100


class PayloadFilter(filters.FilterSet):
    status = filters.ChoiceFilter(choices=PayloadStatus.choices)
    sensor = filters.NumberFilter(field_name="sensor_id")
    search = filters.CharFilter(method="search_filter")
    ordering = filters.OrderingFilter(
        fields=(
            ("sha256", "sha256"),
            ("first_seen", "first_seen"),
            ("size", "size"),
            ("mime_type", "mime_type"),
            ("sensor__name", "sensor"),
            ("signature", "snort_rule"),
            ("vt_detection", "vt_detection"),
            ("status", "status"),
        )
    )

    class Meta:
        model = Payload
        fields: list[str] = []

    def search_filter(self, queryset, name, value):
        term = value.strip()[:SEARCH_MAX]
        if not term:
            return queryset
        q = (
            Q(sha256__icontains=term.lower())
            | Q(filename__icontains=term)
            | Q(mime_type__icontains=term)
            | Q(signature__icontains=term)
            | Q(sensor__name__icontains=term)
        )
        if term.isdigit():
            q |= Q(signature_id=int(term))
        return queryset.filter(q)
