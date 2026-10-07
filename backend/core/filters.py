from django_filters import rest_framework as filters


class DeterministicOrderMixin:
    """Appends the primary key to any ordering so pages never overlap or skip rows."""

    default_ordering = "-pk"

    def filter_queryset(self, queryset):
        qs = super().filter_queryset(queryset)
        ordering = list(qs.query.order_by) or [self.default_ordering]
        return qs.order_by(*ordering, "-pk")


class CharInFilter(filters.BaseInFilter, filters.CharFilter):
    pass
