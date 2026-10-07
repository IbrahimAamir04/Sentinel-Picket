from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from core.testing import client_for, make_alert, make_payload, make_sensor, sha


class PayloadApiTests(TestCase):
    def setUp(self):
        self.c = client_for()
        self.sensor = make_sensor("edge")
        self.p1 = make_payload(1, self.sensor, status="MALICIOUS", vt_malicious=40, vt_suspicious=2, vt_undetected=28, vt_total=70, vt_last_checked=timezone.now(), filename="evil.exe", mime_type="application/x-dosexec", size=500)
        self.p2 = make_payload(2, self.sensor, status="CLEAN", vt_malicious=0, vt_suspicious=0, vt_undetected=70, vt_total=70, vt_last_checked=timezone.now(), size=9000)
        self.p3 = make_payload(3, self.sensor, status="UNKNOWN", size=100)

    def shas(self, q=""):
        return [p["sha256"] for p in self.c.get(f"/api/payloads{q}").json()["results"]]

    def test_list_shape_and_alert_count(self):
        make_alert(self.sensor, payload_available=True, payload_hash=self.p1.sha256)
        make_alert(self.sensor, payload_available=True, payload_hash=self.p1.sha256)
        rows = {p["sha256"]: p for p in self.c.get("/api/payloads").json()["results"]}
        self.assertEqual(rows[self.p1.sha256]["alert_count"], 2)
        self.assertEqual(rows[self.p2.sha256]["alert_count"], 0)
        self.assertEqual(rows[self.p1.sha256]["snort_rule"], "TEST rule")
        self.assertEqual(rows[self.p1.sha256]["sensor_name"], "edge")

    def test_filters_and_search(self):
        self.assertEqual(self.shas("?status=MALICIOUS"), [self.p1.sha256])
        self.assertEqual(self.shas(f"?sensor={self.sensor.pk}").__len__(), 3)
        self.assertEqual(self.shas("?search=evil"), [self.p1.sha256])
        self.assertEqual(self.shas(f"?search={self.p2.sha256[-6:].upper()}"), [self.p2.sha256])
        self.assertEqual(self.shas("?search=dosexec"), [self.p1.sha256])

    def test_sorting_including_vt_detection_with_missing_results(self):
        self.assertEqual(self.shas("?ordering=-size"), [self.p2.sha256, self.p1.sha256, self.p3.sha256])
        self.assertEqual(self.shas("?ordering=-vt_detection")[0], self.p1.sha256)
        self.assertEqual(self.shas("?ordering=-vt_detection")[-1], self.p3.sha256)  # unchecked sorts last
        self.assertEqual(self.c.get("/api/payloads?ordering=bogus").status_code, 400)

    def test_detail_is_case_insensitive_and_validates_the_hash(self):
        self.assertEqual(self.c.get(f"/api/payloads/{self.p1.sha256.upper()}").status_code, 200)
        self.assertEqual(self.c.get("/api/payloads/" + sha(999)).status_code, 404)
        self.assertEqual(self.c.get("/api/payloads/not-a-hash").status_code, 404)
        self.assertEqual(self.c.get("/api/payloads/" + "g" * 64).status_code, 404)

    def test_summary_counts_every_status(self):
        make_payload(4, self.sensor, status="ERROR")
        d = self.c.get("/api/payloads/summary").json()
        self.assertEqual(d, {"UNKNOWN": 1, "CLEAN": 1, "SUSPICIOUS": 0, "MALICIOUS": 1, "ERROR": 1, "total": 4})

    def test_trend_has_14_zero_filled_days_and_folds_error_into_unknown(self):
        make_payload(5, self.sensor, status="ERROR")
        d = self.c.get("/api/payloads/trend").json()
        self.assertEqual(len(d), 14)
        self.assertEqual(sum(sum(v for k, v in day.items() if k != "day") for day in d), 4)
        self.assertEqual(sum(day["UNKNOWN"] for day in d), 2)
        self.assertEqual(self.c.get("/api/payloads/trend?tz=Nowhere/City").status_code, 400)

    def test_virustotal_endpoint_serves_cache_and_never_calls_out(self):
        with mock.patch("socket.socket.connect", side_effect=AssertionError("network used")):
            d = self.c.get(f"/api/payloads/{self.p1.sha256}/virustotal").json()
            none = self.c.get(f"/api/payloads/{self.p3.sha256}/virustotal").json()
        self.assertEqual((d["malicious"], d["total"], d["source"]), (40, 70, "local-cache"))
        self.assertTrue(d["lookup_performed"])
        self.assertFalse(none["lookup_performed"])
        self.assertIsNone(none["total"])

    def test_rescan_unknown_payload_is_404_for_analyst(self):
        r = client_for("ANALYST").post("/api/payloads/" + sha(404) + "/rescan")
        self.assertEqual(r.status_code, 404)

    def test_rescan_never_touches_the_payload(self):
        before = self.p3.updated_at
        client_for("ANALYST").post(f"/api/payloads/{self.p3.sha256}/rescan")
        self.p3.refresh_from_db()
        self.assertEqual(self.p3.updated_at, before)

    def test_old_payloads_fall_outside_trend_window(self):
        make_payload(6, self.sensor, first_seen=timezone.now() - timedelta(days=30), last_seen=timezone.now())
        d = self.c.get("/api/payloads/trend").json()
        self.assertEqual(sum(sum(v for k, v in day.items() if k != "day") for day in d), 3)
