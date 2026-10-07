"""
Strict validation of everything a sensor sends. The collector validates too, but the server never relies on that:
a stolen key or a modified collector must not be able to inject anything the schema does not allow.
"""
import re
from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from rest_framework import serializers

from sensors.models import SensorOS

from . import sanitize

SCHEMA_VERSION = 1
_PROTOCOL = re.compile(r"^[A-Za-z0-9_-]{1,16}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_INT32 = 2_147_483_647


class CleanCharField(serializers.CharField):
    """Free text from the network: control and invisible characters removed, length capped (truncated, not rejected)."""

    def __init__(self, *, clean_max: int, **kwargs):
        self.clean_max = clean_max
        kwargs.setdefault("required", False)
        kwargs.setdefault("allow_blank", True)
        kwargs.setdefault("allow_null", True)
        kwargs.setdefault("max_length", clean_max * 4)  # refuse absurd input outright; truncate merely long input
        super().__init__(**kwargs)

    def to_internal_value(self, data):
        return sanitize.clean_text(super().to_internal_value(data), self.clean_max)


class PayloadMetaSerializer(serializers.Serializer):
    """Metadata only. File or packet content is never sent to or stored by the server."""

    sha256 = serializers.CharField()
    size = serializers.IntegerField(min_value=0, max_value=2**40)
    mime_type = CleanCharField(clean_max=255)
    filename = CleanCharField(clean_max=255)

    def validate_sha256(self, value):
        value = value.strip().lower()
        if not _SHA256.match(value):
            raise serializers.ValidationError("Must be a 64-character hex SHA-256.")
        return value

    def validate_filename(self, value):
        return sanitize.safe_filename(value) if value else value


class EventSerializer(serializers.Serializer):
    timestamp = serializers.DateTimeField()
    signature_id = serializers.IntegerField(min_value=0, max_value=_INT32)
    gid = serializers.IntegerField(min_value=0, max_value=_INT32, required=False, allow_null=True)
    rev = serializers.IntegerField(min_value=0, max_value=_INT32, required=False, allow_null=True)
    signature = CleanCharField(clean_max=512)
    classification = CleanCharField(clean_max=128)
    priority = serializers.IntegerField(min_value=0, max_value=255, required=False, allow_null=True)
    protocol = serializers.CharField(required=False, allow_blank=True, allow_null=True, max_length=16)
    source_ip = serializers.IPAddressField(required=False, allow_null=True)
    source_port = serializers.IntegerField(min_value=0, max_value=65535, required=False, allow_null=True)
    destination_ip = serializers.IPAddressField(required=False, allow_null=True)
    destination_port = serializers.IntegerField(min_value=0, max_value=65535, required=False, allow_null=True)
    pkt_num = serializers.IntegerField(min_value=0, max_value=2**63 - 1, required=False, allow_null=True)
    payload = PayloadMetaSerializer(required=False, allow_null=True)
    raw = serializers.DictField(required=False)

    def validate_timestamp(self, value):
        now = timezone.now()
        if value > now + timedelta(seconds=settings.INGEST_MAX_FUTURE_SKEW_SECONDS):
            raise serializers.ValidationError("Timestamp is in the future. Check the sensor's clock and time zone setting.")
        if value < now - timedelta(days=settings.INGEST_MAX_EVENT_AGE_DAYS):
            raise serializers.ValidationError(f"Timestamp is more than {settings.INGEST_MAX_EVENT_AGE_DAYS} days old.")
        return value

    def validate_protocol(self, value):
        if not value:
            return ""
        if not _PROTOCOL.match(value):
            raise serializers.ValidationError("Unsupported protocol value.")
        return value.upper()

    def validate(self, attrs):
        attrs["priority"] = attrs.get("priority")
        attrs["signature"] = attrs.get("signature") or ""
        attrs["classification"] = attrs.get("classification") or ""
        if not attrs["signature"]:
            gid = attrs.get("gid")
            attrs["signature"] = f"SID {gid if gid is not None else 1}:{attrs['signature_id']}"
        raw = dict(attrs.get("raw") or {})
        raw.pop("b64_data", None)  # packet bytes are never persisted, whatever the collector sent
        attrs["raw"] = raw
        return attrs


class EnvelopeSerializer(serializers.Serializer):
    schema = serializers.IntegerField()
    events = serializers.ListField(child=serializers.DictField(), allow_empty=False)

    def validate_schema(self, value):
        if value != SCHEMA_VERSION:
            raise serializers.ValidationError(f"Unsupported schema version. This server accepts schema {SCHEMA_VERSION}.")
        return value

    def validate_events(self, value):
        if len(value) > settings.INGEST_MAX_EVENTS_PER_REQUEST:
            raise serializers.ValidationError(f"At most {settings.INGEST_MAX_EVENTS_PER_REQUEST} events per request.")
        return value


class HeartbeatSerializer(serializers.Serializer):
    hostname = CleanCharField(clean_max=255)
    os = serializers.ChoiceField(choices=[o.value for o in SensorOS], required=False, allow_null=True)
    ip = serializers.IPAddressField(required=False, allow_null=True)
    snort_version = CleanCharField(clean_max=32)
    collector_version = CleanCharField(clean_max=32)
