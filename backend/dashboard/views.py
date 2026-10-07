from django.db.models import Max
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from alerts.models import Alert
from core.timeutils import parse_tz
from sensors.models import Sensor

from . import services


class StatsView(APIView):
    def get(self, request):
        return Response(services.stats())


class TimelineView(APIView):
    def get(self, request):
        range_key = request.query_params.get("range", "24h")
        if range_key not in {"24h", "7d"}:
            raise ValidationError({"range": "Use 24h or 7d."})
        return Response(services.timeline(range_key, parse_tz(request)))


class ProtocolsView(APIView):
    def get(self, request):
        return Response(services.protocols())


class RulesView(APIView):
    def get(self, request):
        try:
            limit = int(request.query_params.get("limit", 8))
        except ValueError:
            raise ValidationError({"limit": "Must be an integer."})
        return Response(services.top_rules(min(max(limit, 1), 50)))


class FilterOptionsView(APIView):
    """Values for the filter dropdowns on the alerts and payloads pages."""

    def get(self, request):
        rules = Alert.objects.values("signature_id").annotate(signature=Max("signature")).order_by("signature")
        return Response(
            {
                "sensors": list(Sensor.objects.values("id", "name")),
                "protocols": list(
                    Alert.objects.exclude(protocol="").order_by("protocol").values_list("protocol", flat=True).distinct()
                ),
                "rules": list(rules),
            }
        )
