import logging

from django.conf import settings
from django.utils import timezone
from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.response import Response
from rest_framework.views import APIView

from sensors.models import Sensor

from . import services
from .authentication import SensorKeyAuthentication
from .parsers import BoundedJSONParser
from .permissions import IsSensor
from .serializers import EnvelopeSerializer, EventSerializer, HeartbeatSerializer
from .throttles import HeartbeatThrottle, IngestThrottle

log = logging.getLogger("sentinel.ingestion")
MAX_REPORTED_ERRORS = 50


class DemoModeActive(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = "Ingestion is disabled while the server is in demo mode."
    default_code = "demo_mode"


class SensorAPIView(APIView):
    """Base for endpoints used by collectors: sensor-key auth only, JSON only, never open in demo mode."""

    authentication_classes = [SensorKeyAuthentication]
    permission_classes = [IsSensor]
    parser_classes = [BoundedJSONParser]

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        if settings.SENTINEL_DEMO_MODE:
            # Real telemetry must never mix with synthetic data.
            raise DemoModeActive()

    @staticmethod
    def touch(sensor: Sensor, **fields) -> None:
        """Health comes from the server's clock, never from a timestamp the sensor supplies."""
        Sensor.objects.filter(pk=sensor.pk).update(last_seen=timezone.now(), updated_at=timezone.now(), **fields)


class IngestEventsView(SensorAPIView):
    throttle_classes = [IngestThrottle]

    def post(self, request):
        sensor = request.auth
        envelope = EnvelopeSerializer(data=request.data)
        envelope.is_valid(raise_exception=True)

        valid, rejected = [], []
        for index, raw in enumerate(envelope.validated_data["events"]):
            ser = EventSerializer(data=raw)
            if ser.is_valid():
                valid.append((index, ser.validated_data))
            else:
                rejected.append({"index": index, "errors": ser.errors})

        result = services.ingest(sensor, valid)
        rejected += result.rejected
        self.touch(sensor)

        total = len(envelope.validated_data["events"])
        log.info("sensor=%s received=%d accepted=%d duplicates=%d rejected=%d", sensor.name, total, result.accepted, result.duplicates, len(rejected))
        return Response({
            "received": total,
            "accepted": result.accepted,
            "duplicates": result.duplicates,
            "rejected": len(rejected),
            "errors": sorted(rejected, key=lambda r: r["index"])[:MAX_REPORTED_ERRORS],
        }, status=status.HTTP_200_OK)


class HeartbeatView(SensorAPIView):
    throttle_classes = [HeartbeatThrottle]

    def post(self, request):
        ser = HeartbeatSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        # Only fields the sensor actually reported are updated; absent ones never blank out stored values.
        fields = {k: v for k, v in ser.validated_data.items() if v not in (None, "")}
        self.touch(request.auth, **fields)
        return Response({"status": "ok", "server_time": timezone.now().isoformat()})
