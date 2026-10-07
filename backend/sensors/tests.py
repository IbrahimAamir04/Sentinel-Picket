from datetime import timedelta

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from core.testing import client_for, make_sensor
from sensors.models import derive_status


class DeriveStatusTests(SimpleTestCase):
    def test_thresholds(self):
        now = timezone.now()
        self.assertEqual(derive_status(now - timedelta(seconds=119), now), "ONLINE")
        self.assertEqual(derive_status(now - timedelta(seconds=120), now), "WARNING")
        self.assertEqual(derive_status(now - timedelta(seconds=599), now), "WARNING")
        self.assertEqual(derive_status(now - timedelta(seconds=600), now), "OFFLINE")

    def test_never_seen_is_offline(self):
        self.assertEqual(derive_status(None), "OFFLINE")


class SensorApiTests(TestCase):
    def test_status_is_derived_from_last_seen_not_stored(self):
        make_sensor("fresh", seconds_ago=10)
        make_sensor("late", seconds_ago=300)
        make_sensor("dead", seconds_ago=7200)
        make_sensor("never", seconds_ago=None)
        data = {s["name"]: s["status"] for s in client_for().get("/api/sensors").json()}
        self.assertEqual(data, {"fresh": "ONLINE", "late": "WARNING", "dead": "OFFLINE", "never": "OFFLINE"})

    def test_changing_last_seen_changes_status_immediately(self):
        s = make_sensor("flip", seconds_ago=3000)
        c = client_for()
        self.assertEqual(c.get(f"/api/sensors/{s.pk}").json()["status"], "OFFLINE")
        s.last_seen = timezone.now()
        s.save()
        self.assertEqual(c.get(f"/api/sensors/{s.pk}").json()["status"], "ONLINE")

    def test_list_is_a_plain_array(self):
        make_sensor()
        self.assertIsInstance(client_for().get("/api/sensors").json(), list)
