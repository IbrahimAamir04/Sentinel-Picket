from unittest import mock

from django.core.cache import cache
from django.test import TestCase, override_settings
from rest_framework.test import APIClient
from rest_framework.throttling import SimpleRateThrottle

from alerts.models import Alert
from core.testing import batch, client_for, event, make_registered_sensor, make_sensor, sensor_client
from sensors import keys
from sensors.models import Sensor


class SensorKeyTests(TestCase):
    def setUp(self):
        cache.clear()
        self.sensor, self.key = make_registered_sensor("edge")

    def post(self, key, body=None):
        return sensor_client(key).post("/api/ingest/events", body or batch(event()), format="json")

    def test_valid_key_is_accepted(self):
        self.assertEqual(self.post(self.key).status_code, 200)

    def test_missing_key_is_401_with_bearer_challenge(self):
        r = APIClient().post("/api/ingest/events", batch(event()), format="json")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r["WWW-Authenticate"], "Bearer")

    def test_wrong_key_unknown_prefix_and_garbage_all_look_identical(self):
        bodies = set()
        for bad in (keys.KEY_PREFIX + "x" * 43, "snt_" + self.key[4:12] + "tampered" * 4, "not-a-key", ""):
            r = self.post(bad) if bad else APIClient().post("/api/ingest/events", batch(event()), format="json", HTTP_AUTHORIZATION="Bearer")
            self.assertEqual(r.status_code, 401, bad)
            bodies.add(r.json()["detail"])
        self.assertEqual(bodies, {"Invalid sensor credentials."})  # never reveals which part was wrong

    def test_disabled_sensor_is_rejected_with_the_same_generic_message(self):
        self.sensor.is_active = False
        self.sensor.save()
        r = self.post(self.key)
        self.assertEqual((r.status_code, r.json()["detail"]), (401, "Invalid sensor credentials."))

    def test_only_a_digest_is_stored_never_the_key(self):
        self.sensor.refresh_from_db()
        self.assertNotIn(self.key, (self.sensor.api_key_hash, self.sensor.api_key_prefix))
        self.assertEqual(self.sensor.api_key_hash, keys.hash_key(self.key))
        self.assertEqual(len(self.sensor.api_key_hash), 64)

    def test_rotation_invalidates_the_old_key_immediately(self):
        new = self.sensor.issue_api_key()
        self.assertEqual(self.post(self.key).status_code, 401)
        self.assertEqual(self.post(new).status_code, 200)

    def test_sensors_without_a_key_cannot_authenticate(self):
        make_sensor("demo-like")
        self.assertEqual(self.post("snt_" + "0" * 43).status_code, 401)

    def test_repeated_bad_keys_are_throttled_but_a_good_key_still_works(self):
        with override_settings(INGEST_AUTH_FAIL_LIMIT=3):
            codes = [self.post("snt_" + "z" * 43).status_code for _ in range(6)]
            self.assertEqual(codes[:3], [401, 401, 401])
            self.assertIn(429, codes[3:])
            self.assertEqual(self.post(self.key).status_code, 200)

    def test_failed_key_is_never_logged(self):
        with self.assertLogs("sentinel.security", level="WARNING") as logs:
            self.post("snt_SECRETSECRETSECRETSECRETSECRETSECRET12")
        self.assertNotIn("SECRETSECRET", " ".join(logs.output))


class SeparationOfCredentialsTests(TestCase):
    def test_a_sensor_key_cannot_read_the_dashboard_api(self):
        _, key = make_registered_sensor()
        for url in ("/api/alerts", "/api/sensors", "/api/dashboard/stats", "/api/payloads", "/api/auth/me"):
            self.assertEqual(sensor_client(key).get(url).status_code, 401, url)

    def test_a_signed_in_person_cannot_ingest_even_as_admin(self):
        from core.testing import PASSWORD, make_user

        admin = make_user("ADMIN")
        c = APIClient()
        self.assertTrue(c.login(username=admin.username, password=PASSWORD))  # a real session cookie, not a shortcut
        self.assertEqual(c.get("/api/auth/me").status_code, 200)
        r = c.post("/api/ingest/events", batch(event()), format="json")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(Alert.objects.count(), 0)

    def test_ingest_endpoints_accept_post_only(self):
        _, key = make_registered_sensor()
        for url in ("/api/ingest/events", "/api/ingest/heartbeat"):
            self.assertEqual(sensor_client(key).get(url).status_code, 405, url)


class DemoModeGuardTests(TestCase):
    @override_settings(SENTINEL_DEMO_MODE=True)
    def test_ingestion_is_refused_in_demo_mode(self):
        _, key = make_registered_sensor()
        for url, body in (("/api/ingest/events", batch(event())), ("/api/ingest/heartbeat", {"hostname": "x"})):
            self.assertEqual(sensor_client(key).post(url, body, format="json").status_code, 409, url)
        self.assertEqual(Alert.objects.count(), 0)


class ThrottleTests(TestCase):
    def setUp(self):
        cache.clear()

    def test_ingest_is_limited_per_sensor_not_globally(self):
        _, k1 = make_registered_sensor("a")
        _, k2 = make_registered_sensor("b")
        with mock.patch.dict(SimpleRateThrottle.THROTTLE_RATES, {"ingest": "2/min"}):
            codes = [sensor_client(k1).post("/api/ingest/events", batch(event(pkt_num=i)), format="json").status_code for i in range(4)]
            other = sensor_client(k2).post("/api/ingest/events", batch(event()), format="json").status_code
        cache.clear()
        self.assertEqual(codes, [200, 200, 429, 429])
        self.assertEqual(other, 200)


class OversizedBodyTests(TestCase):
    @override_settings(INGEST_MAX_BODY_BYTES=2000)
    def test_body_over_the_limit_is_413_and_nothing_is_stored(self):
        _, key = make_registered_sensor()
        big = batch(*[event(pkt_num=i) for i in range(40)])
        self.assertEqual(sensor_client(key).post("/api/ingest/events", big, format="json").status_code, 413)
        self.assertEqual(Alert.objects.count(), 0)


class CommandTests(TestCase):
    def run_cmd(self, *args):
        from io import StringIO

        from django.core.management import call_command

        out = StringIO()
        call_command(*args, stdout=out)
        return out.getvalue()

    def test_register_prints_the_key_once_and_it_works(self):
        out = self.run_cmd("register_sensor", "--name", "cli-sensor", "--os", "windows")
        key = next(w for w in out.split() if w.startswith("snt_"))
        sensor = Sensor.objects.get(name="cli-sensor")
        self.assertEqual(sensor.os, "WINDOWS")
        self.assertEqual(sensor_client(key).post("/api/ingest/events", batch(event()), format="json").status_code, 200)

    def test_register_refuses_duplicates_and_demo_mode(self):
        from django.core.management.base import CommandError

        self.run_cmd("register_sensor", "--name", "dup", "--os", "linux")
        with self.assertRaises(CommandError):
            self.run_cmd("register_sensor", "--name", "dup", "--os", "linux")
        with override_settings(SENTINEL_DEMO_MODE=True), self.assertRaises(CommandError):
            self.run_cmd("register_sensor", "--name", "other", "--os", "linux")

    def test_rotate_command(self):
        from django.core.management.base import CommandError

        out = self.run_cmd("register_sensor", "--name", "rot", "--os", "linux")
        old = next(w for w in out.split() if w.startswith("snt_"))
        new = next(w for w in self.run_cmd("rotate_sensor_key", "--name", "rot").split() if w.startswith("snt_"))
        self.assertNotEqual(old, new)
        self.assertEqual(sensor_client(old).post("/api/ingest/heartbeat", {}, format="json").status_code, 401)
        with self.assertRaises(CommandError):
            self.run_cmd("rotate_sensor_key", "--name", "missing")

    def test_seed_demo_refuses_when_real_sensors_exist(self):
        from django.core.management.base import CommandError

        make_registered_sensor("real")
        with override_settings(SENTINEL_DEMO_MODE=True), self.assertRaises(CommandError):
            self.run_cmd("seed_demo", "--reset")
        self.assertTrue(Sensor.objects.filter(name="real").exists())
