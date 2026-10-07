from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings

from alerts.models import Alert
from payloads.models import Payload
from sensors.models import Sensor


class DemoSeedTests(TestCase):
    @override_settings(SENTINEL_DEMO_MODE=False)
    def test_refuses_to_run_outside_demo_mode(self):
        with self.assertRaises(CommandError):
            call_command("seed_demo")
        self.assertEqual(Alert.objects.count(), 0)

    @override_settings(SENTINEL_DEMO_MODE=True)
    def test_seeds_consistent_synthetic_data(self):
        call_command("seed_demo", verbosity=0)
        self.assertEqual((Sensor.objects.count(), Payload.objects.count(), Alert.objects.count()), (4, 72, 720))
        # every alert that claims a payload points at a payload that exists
        hashes = set(Payload.objects.values_list("sha256", flat=True))
        for h in Alert.objects.filter(payload_available=True).values_list("payload_hash", flat=True):
            self.assertIn(h, hashes)
        # only documentation address ranges are used for external hosts
        for ip in Alert.objects.values_list("source_ip", flat=True)[:50]:
            self.assertTrue(ip.startswith(("10.", "203.0.113.", "198.51.100.", "192.0.2.")), ip)
        # sensor health mix is derived, not assigned
        self.assertEqual(sorted(s.status for s in Sensor.objects.all()), ["OFFLINE", "ONLINE", "ONLINE", "WARNING"])

    @override_settings(SENTINEL_DEMO_MODE=True)
    def test_never_overwrites_existing_data_without_reset(self):
        call_command("seed_demo", verbosity=0)
        with self.assertRaises(CommandError):
            call_command("seed_demo", verbosity=0)
        call_command("seed_demo", "--reset", verbosity=0)
        self.assertEqual(Alert.objects.count(), 720)

    @override_settings(SENTINEL_DEMO_MODE=True, DEBUG=False)
    def test_demo_users_are_refused_when_not_debug(self):
        with self.assertRaises(CommandError):
            call_command("seed_demo", "--users-password", "x", verbosity=0)


class MetaModeTests(TestCase):
    def test_meta_reflects_demo_flag(self):
        from rest_framework.test import APIClient

        with override_settings(SENTINEL_DEMO_MODE=True):
            self.assertEqual(APIClient().get("/api/meta").json()["mode"], "demo")
        with override_settings(SENTINEL_DEMO_MODE=False):
            self.assertEqual(APIClient().get("/api/meta").json()["mode"], "live")
