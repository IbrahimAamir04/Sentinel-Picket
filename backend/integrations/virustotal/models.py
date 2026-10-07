from django.db import models

from core.validators import sha256_validator


class VirusTotalResult(models.Model):
    """
    Cache of VirusTotal hash lookups so the same hash is never queried twice within the cache window and
    rate limits are respected. Populated by the Phase 4 service; nothing writes to it yet.
    """

    class Outcome(models.TextChoices):
        FOUND = "FOUND", "Found"
        NOT_FOUND = "NOT_FOUND", "Not found"
        ERROR = "ERROR", "Error"

    sha256 = models.CharField(max_length=64, primary_key=True, validators=[sha256_validator])
    outcome = models.CharField(max_length=10, choices=Outcome.choices)
    malicious = models.PositiveIntegerField(null=True, blank=True)
    suspicious = models.PositiveIntegerField(null=True, blank=True)
    undetected = models.PositiveIntegerField(null=True, blank=True)
    total = models.PositiveIntegerField(null=True, blank=True)
    error_message = models.CharField(max_length=255, blank=True)
    fetched_at = models.DateTimeField()

    def __str__(self) -> str:
        return f"{self.sha256[:12]}… {self.outcome}"
