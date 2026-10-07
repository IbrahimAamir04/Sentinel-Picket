import logging

from django.conf import settings
from django.core.cache import cache
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed, Throttled

from sensors import keys
from sensors.models import Sensor

log = logging.getLogger("sentinel.security")
FAIL_WINDOW = 60


class SensorPrincipal:
    """What `request.user` is for an ingestion request: a sensor, never a person."""

    is_authenticated = True
    is_anonymous = False

    def __init__(self, sensor: Sensor):
        self.sensor = sensor
        self.pk = sensor.pk

    def __str__(self) -> str:
        return f"sensor:{self.sensor.name}"


def _client_ip(request) -> str:
    return request.META.get("REMOTE_ADDR", "unknown")


def _register_failure(request) -> None:
    """Failed keys are throttled per client address. Valid keys are never blocked by this."""
    cache_key = f"ingest-auth-fail:{_client_ip(request)}"
    cache.add(cache_key, 0, FAIL_WINDOW)
    try:
        count = cache.incr(cache_key)
    except ValueError:
        cache.set(cache_key, 1, FAIL_WINDOW)
        count = 1
    log.warning("Rejected sensor credential from %s", _client_ip(request))  # never the credential itself
    if count > settings.INGEST_AUTH_FAIL_LIMIT:
        raise Throttled(wait=FAIL_WINDOW)


class SensorKeyAuthentication(BaseAuthentication):
    """`Authorization: Bearer snt_...`. Separate from session login: a sensor key cannot read the dashboard API and vice versa."""

    def authenticate_header(self, request):
        return "Bearer"

    def authenticate(self, request):
        header = get_authorization_header(request).split()
        if not header or header[0].lower() != b"bearer":
            return None
        if len(header) != 2:
            _register_failure(request)
            raise AuthenticationFailed("Invalid sensor credentials.")
        try:
            key = header[1].decode("ascii")
        except UnicodeDecodeError:
            _register_failure(request)
            raise AuthenticationFailed("Invalid sensor credentials.")

        sensor = Sensor.objects.filter(api_key_prefix=keys.lookup_prefix(key)).first() if key.startswith(keys.KEY_PREFIX) else None
        # One generic message for unknown, mismatched and disabled sensors, so a caller learns nothing about which it was.
        if sensor is None or not sensor.is_active or not keys.key_matches(key, sensor.api_key_hash):
            _register_failure(request)
            raise AuthenticationFailed("Invalid sensor credentials.")
        return SensorPrincipal(sensor), sensor
