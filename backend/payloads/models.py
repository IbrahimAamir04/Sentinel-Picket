from django.db import models

from core.validators import sha256_validator


class PayloadStatus(models.TextChoices):
    UNKNOWN = "UNKNOWN", "Unknown"
    CLEAN = "CLEAN", "Clean"
    SUSPICIOUS = "SUSPICIOUS", "Suspicious"
    MALICIOUS = "MALICIOUS", "Malicious"
    ERROR = "ERROR", "Error"


class Payload(models.Model):
    """
    Metadata about a captured file, keyed by its SHA-256. The file content itself is never stored in the
    database and is never executed or rendered.
    """

    sha256 = models.CharField(max_length=64, primary_key=True, validators=[sha256_validator])
    sensor = models.ForeignKey("sensors.Sensor", on_delete=models.PROTECT, related_name="payloads")
    first_seen = models.DateTimeField(db_index=True)
    last_seen = models.DateTimeField()
    size = models.PositiveBigIntegerField()
    mime_type = models.CharField(max_length=255, blank=True)
    filename = models.CharField(max_length=255, null=True, blank=True)
    # Rule that first produced this payload, copied from the originating alert at ingestion time.
    signature_id = models.PositiveIntegerField(null=True, blank=True)
    signature = models.CharField(max_length=512, blank=True)
    status = models.CharField(max_length=12, choices=PayloadStatus.choices, default=PayloadStatus.UNKNOWN, db_index=True)
    vt_malicious = models.PositiveIntegerField(null=True, blank=True)
    vt_suspicious = models.PositiveIntegerField(null=True, blank=True)
    vt_undetected = models.PositiveIntegerField(null=True, blank=True)
    vt_total = models.PositiveIntegerField(null=True, blank=True)
    vt_last_checked = models.DateTimeField(null=True, blank=True)
    # Set only after an explicit, user-confirmed external upload (Phase 4).
    vt_submitted_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-first_seen"]

    def __str__(self) -> str:
        return self.sha256
