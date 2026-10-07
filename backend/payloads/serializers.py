from rest_framework import serializers

from .models import Payload


class PayloadSerializer(serializers.ModelSerializer):
    sensor_id = serializers.IntegerField(read_only=True)
    sensor_name = serializers.CharField(source="sensor.name", read_only=True)
    snort_rule = serializers.CharField(source="signature", read_only=True)
    alert_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = Payload
        fields = [
            "sha256", "sensor_id", "sensor_name", "first_seen", "last_seen", "size", "mime_type", "filename",
            "status", "snort_rule", "signature_id", "vt_malicious", "vt_suspicious", "vt_undetected",
            "vt_total", "vt_last_checked", "vt_submitted_at", "alert_count",
        ]
        read_only_fields = fields
