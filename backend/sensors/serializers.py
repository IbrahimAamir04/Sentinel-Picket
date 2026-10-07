from rest_framework import serializers

from .models import Sensor


class SensorSerializer(serializers.ModelSerializer):
    status = serializers.CharField(read_only=True)  # derived from last_seen
    snort_version = serializers.CharField(read_only=True)

    class Meta:
        model = Sensor
        fields = ["id", "name", "hostname", "os", "ip", "snort_version", "status", "last_seen"]
        read_only_fields = fields
