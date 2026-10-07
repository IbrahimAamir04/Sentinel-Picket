from rest_framework import serializers

from .models import Alert


class AlertSerializer(serializers.ModelSerializer):
    sensor_name = serializers.CharField(source="sensor.name", read_only=True)

    class Meta:
        model = Alert
        fields = [
            "id", "sensor_id", "sensor_name", "timestamp", "signature_id", "signature", "classification",
            "priority", "severity", "protocol", "source_ip", "source_port", "destination_ip",
            "destination_port", "payload_available", "payload_hash", "payload_size",
        ]
        read_only_fields = fields
