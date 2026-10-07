from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from core.testing import client_for, make_alert, make_payload, make_sensor


class StatsTests(TestCase):
    def setUp(self):
        self.c = client_for()

    def test_empty_database_gives_zeros_not_errors(self):
        d = self.c.get("/api/dashboard/stats").json()
        self.assertEqual(d["total_alerts"], 0)
        self.assertEqual(d["by_severity"], {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0})
        self.assertEqual(d["detection_rate"], 0)
        self.assertEqual(d["classifications"], [])

    def test_numbers_come_from_the_database(self):
        s = make_sensor()
        for sev, n in (("CRITICAL", 2), ("HIGH", 3), ("MEDIUM", 1), ("LOW", 4)):
            for _ in range(n):
                make_alert(s, severity=sev, classification="a" if sev == "LOW" else "b")
        d = self.c.get("/api/dashboard/stats").json()
        self.assertEqual(d["total_alerts"], 10)
        self.assertEqual(d["by_severity"], {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 1, "LOW": 4})
        self.assertEqual(d["classifications"], [{"name": "b", "count": 6}, {"name": "a", "count": 4}])
        make_alert(s, severity="LOW")
        self.assertEqual(self.c.get("/api/dashboard/stats").json()["total_alerts"], 11)

    def test_detection_rate_is_malicious_over_checked(self):
        s = make_sensor()
        chk = dict(vt_total=70, vt_malicious=1, vt_undetected=69, vt_suspicious=0, vt_last_checked=timezone.now())
        make_payload(1, s, status="MALICIOUS", **chk)
        make_payload(2, s, status="MALICIOUS", **chk)
        make_payload(3, s, status="CLEAN", **chk)
        make_payload(4, s, status="UNKNOWN")  # never checked: excluded from the denominator
        d = self.c.get("/api/dashboard/stats").json()
        self.assertEqual((d["total_payloads"], d["malicious_payloads"], d["checked_payloads"]), (4, 2, 3))
        self.assertAlmostEqual(d["detection_rate"], 2 / 3)


class TimelineTests(TestCase):
    def setUp(self):
        self.c = client_for()
        self.s = make_sensor()

    def test_24h_has_24_buckets_and_counts_by_severity(self):
        make_alert(self.s, severity="HIGH", timestamp=timezone.now() - timedelta(minutes=10))
        make_alert(self.s, severity="HIGH", timestamp=timezone.now() - timedelta(minutes=11))
        make_alert(self.s, severity="LOW", timestamp=timezone.now() - timedelta(hours=5))
        make_alert(self.s, severity="LOW", timestamp=timezone.now() - timedelta(hours=30))  # outside window
        d = self.c.get("/api/dashboard/timeline?range=24h").json()
        self.assertEqual(len(d), 24)
        self.assertEqual(sum(p["HIGH"] for p in d), 2)
        self.assertEqual(sum(p["LOW"] for p in d), 1)
        self.assertEqual(d, sorted(d, key=lambda p: p["bucket"]))

    def test_7d_has_7_buckets_and_respects_time_zone(self):
        make_alert(self.s, severity="MEDIUM", timestamp=timezone.now() - timedelta(days=2))
        for tz in ("UTC", "Asia/Karachi", "America/Los_Angeles"):
            d = self.c.get(f"/api/dashboard/timeline?range=7d&tz={tz}").json()
            self.assertEqual(len(d), 7, tz)
            self.assertEqual(sum(p["MEDIUM"] for p in d), 1, tz)

    def test_validation(self):
        self.assertEqual(self.c.get("/api/dashboard/timeline?range=1y").status_code, 400)
        self.assertEqual(self.c.get("/api/dashboard/timeline?tz=Mars/Base").status_code, 400)

    def test_default_range_is_24h(self):
        self.assertEqual(len(self.c.get("/api/dashboard/timeline").json()), 24)


class BreakdownTests(TestCase):
    def setUp(self):
        self.c = client_for()
        s = make_sensor()
        for _ in range(3):
            make_alert(s, protocol="TCP", signature_id=1, signature="one")
        make_alert(s, protocol="UDP", signature_id=2, signature="two")
        make_alert(s, protocol="", signature_id=3, signature="three")

    def test_protocols_skip_blank_and_sort_by_count(self):
        self.assertEqual(self.c.get("/api/dashboard/protocols").json(), [{"protocol": "TCP", "count": 3}, {"protocol": "UDP", "count": 1}])

    def test_top_rules_with_limit(self):
        d = self.c.get("/api/dashboard/rules?limit=2").json()
        self.assertEqual([r["signature_id"] for r in d], [1, 2])
        self.assertEqual(d[0]["count"], 3)
        self.assertEqual(self.c.get("/api/dashboard/rules?limit=abc").status_code, 400)
        self.assertEqual(len(self.c.get("/api/dashboard/rules?limit=9999").json()), 3)

    def test_filter_options(self):
        d = self.c.get("/api/dashboard/filters").json()
        self.assertEqual(d["protocols"], ["TCP", "UDP"])
        self.assertEqual(len(d["rules"]), 3)
        self.assertEqual(len(d["sensors"]), 1)
