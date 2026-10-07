from django.conf import settings
from django.db import models
from django.utils import timezone

from . import keys


class SensorOS(models.TextChoices):
    LINUX = "LINUX", "Linux"
    WINDOWS = "WINDOWS", "Windows"


class SensorStatus(models.TextChoices):
    ONLINE = "ONLINE", "Online"
    WARNING = "WARNING", "Warning"
    OFFLINE = "OFFLINE", "Offline"


def derive_status(last_seen, now=None) -> str:
    """The single rule for sensor health. Status is never stored: a stored value would go stale the moment a sensor dies."""
    if last_seen is None:
        return SensorStatus.OFFLINE
    age = ((now or timezone.now()) - last_seen).total_seconds()
    if age >= settings.SENSOR_OFFLINE_AFTER_SECONDS:
        return SensorStatus.OFFLINE
    if age >= settings.SENSOR_WARNING_AFTER_SECONDS:
        return SensorStatus.WARNING
    return SensorStatus.ONLINE


class Sensor(models.Model):
    name = models.CharField(max_length=100, unique=True)
    hostname = models.CharField(max_length=255, blank=True)
    os = models.CharField(max_length=10, choices=SensorOS.choices)
    ip = models.GenericIPAddressField(null=True, blank=True)
    snort_version = models.CharField(max_length=32, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    collector_version = models.CharField(max_length=32, blank=True)
    # Ingestion credentials. Only a digest is stored; see sensors/keys.py. A disabled sensor is rejected by the ingestion API.
    is_active = models.BooleanField(default=True)
    api_key_prefix = models.CharField(max_length=16, unique=True, null=True, blank=True, editable=False)
    api_key_hash = models.CharField(max_length=64, blank=True, editable=False)
    api_key_created_at = models.DateTimeField(null=True, blank=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name

    @property
    def status(self) -> str:
        return derive_status(self.last_seen)

    @property
    def has_api_key(self) -> bool:
        return bool(self.api_key_hash)

    def issue_api_key(self) -> str:
        """Create and store a new key, invalidating any previous one. Returns the plaintext key: show it once, never log it."""
        for _ in range(5):
            key = keys.generate_key()
            if not Sensor.objects.filter(api_key_prefix=keys.lookup_prefix(key)).exists():
                break
        self.api_key_prefix = keys.lookup_prefix(key)
        self.api_key_hash = keys.hash_key(key)
        self.api_key_created_at = timezone.now()
        self.save(update_fields=["api_key_prefix", "api_key_hash", "api_key_created_at", "updated_at"])
        return key
