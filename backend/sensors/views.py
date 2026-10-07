from rest_framework import viewsets

from .models import Sensor
from .serializers import SensorSerializer


class SensorViewSet(viewsets.ReadOnlyModelViewSet):
    """Sensors are created and updated by the ingestion layer (Phase 3), not through this API."""

    queryset = Sensor.objects.all()
    serializer_class = SensorSerializer
    pagination_class = None
