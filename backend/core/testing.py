"""Small factories shared by the test suites."""
from datetime import timedelta
from itertools import count

from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient

from alerts.models import Alert
from payloads.models import Payload
from sensors.models import Sensor

PASSWORD = "T3st-Passw0rd-long-enough!"
_n = count(1)


def make_user(role="VIEWER", username=None, **extra):
    User = get_user_model()
    return User.objects.create_user(username=username or f"user{next(_n)}", password=PASSWORD, role=role, **extra)


def client_for(role="VIEWER"):
    c = APIClient()
    c.force_authenticate(make_user(role))
    return c


def make_sensor(name=None, os="LINUX", seconds_ago=5, **extra):
    n = next(_n)
    last = None if seconds_ago is None else timezone.now() - timedelta(seconds=seconds_ago)
    return Sensor.objects.create(name=name or f"sensor-{n}", os=os, last_seen=last, **extra)


def sha(i: int) -> str:
    return f"{i:064x}"


def make_alert(sensor=None, **kw):
    sensor = sensor or make_sensor()
    data = dict(
        timestamp=timezone.now() - timedelta(minutes=1), signature_id=1000001, signature="TEST rule",
        classification="trojan-activity", priority=1, severity="HIGH", protocol="TCP",
        source_ip="203.0.113.5", source_port=4444, destination_ip="10.0.0.5", destination_port=80,
    )
    data.update(kw)
    return Alert.objects.create(sensor=sensor, **data)


def make_payload(i=None, sensor=None, **kw):
    i = i if i is not None else next(_n)
    sensor = sensor or make_sensor()
    now = timezone.now()
    data = dict(sha256=sha(i), sensor=sensor, first_seen=now - timedelta(hours=1), last_seen=now, size=1234,
                mime_type="application/zip", signature_id=1000001, signature="TEST rule")
    data.update(kw)
    return Payload.objects.create(**data)


# --- ingestion helpers -------------------------------------------------------------------------------------
def make_registered_sensor(name=None, os="LINUX", **extra):
    """A sensor with an API key. Returns (sensor, plaintext_key)."""
    sensor = make_sensor(name=name, os=os, seconds_ago=None, **extra)
    return sensor, sensor.issue_api_key()


def sensor_client(key):
    c = APIClient()
    if key:
        c.credentials(HTTP_AUTHORIZATION=f"Bearer {key}")
    return c


def event(**overrides):
    """A valid normalised event as the collector sends it. Override or set a field to None to drop it."""
    e = {
        "timestamp": (timezone.now() - timedelta(seconds=30)).isoformat(),
        "signature_id": 1000101, "gid": 1, "rev": 2, "signature": "TEST trojan beacon",
        "classification": "trojan-activity", "priority": 1, "protocol": "TCP",
        "source_ip": "10.0.0.5", "source_port": 44321, "destination_ip": "203.0.113.9", "destination_port": 80,
        "pkt_num": 1,
    }
    e.update(overrides)
    return {k: v for k, v in e.items() if v is not Ellipsis}


def batch(*events):
    return {"schema": 1, "events": list(events)}
