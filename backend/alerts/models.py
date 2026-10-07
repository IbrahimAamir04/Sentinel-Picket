from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

from core.validators import sha256_validator


class Severity(models.TextChoices):
    CRITICAL = "CRITICAL", "Critical"
    HIGH = "HIGH", "High"
    MEDIUM = "MEDIUM", "Medium"
    LOW = "LOW", "Low"


PORT = [MinValueValidator(0), MaxValueValidator(65535)]


class Alert(models.Model):
    """One Snort alert. Everything the sensor did not provide stays null; nothing is invented."""

    sensor = models.ForeignKey("sensors.Sensor", on_delete=models.PROTECT, related_name="alerts")
    timestamp = models.DateTimeField(db_index=True)
    signature_id = models.PositiveIntegerField()
    signature = models.CharField(max_length=512)
    classification = models.CharField(max_length=128, blank=True)
    priority = models.PositiveSmallIntegerField(null=True, blank=True)
    severity = models.CharField(max_length=10, choices=Severity.choices)
    protocol = models.CharField(max_length=16, blank=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    source_port = models.PositiveIntegerField(null=True, blank=True, validators=PORT)
    destination_ip = models.GenericIPAddressField(null=True, blank=True)
    destination_port = models.PositiveIntegerField(null=True, blank=True, validators=PORT)
    payload_available = models.BooleanField(default=False)
    payload_hash = models.CharField(max_length=64, null=True, blank=True, db_index=True, validators=[sha256_validator])
    payload_size = models.PositiveBigIntegerField(null=True, blank=True)
    # Deterministic identity of the event, so a collector retry can never create a duplicate. Null for demo data.
    event_id = models.CharField(max_length=64, null=True, blank=True, editable=False)
    # Untrusted, as received from the sensor. Stored for forensics; not exposed through the API in Phase 2.
    raw_event = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp", "-id"]
        indexes = [
            models.Index(fields=["severity", "-timestamp"]),
            models.Index(fields=["signature_id"]),
            models.Index(fields=["sensor", "-timestamp"]),
            models.Index(fields=["protocol"]),
        ]
        constraints = [
            models.UniqueConstraint(fields=["sensor", "event_id"], condition=models.Q(event_id__isnull=False), name="alert_unique_event_per_sensor"),
            models.CheckConstraint(
                condition=models.Q(payload_available=False) | models.Q(payload_hash__isnull=False),
                name="alert_payload_requires_hash",
            )
        ]

    def __str__(self) -> str:
        return f"[{self.severity}] {self.signature}"
