from datetime import timedelta

from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from alerts.models import Alert
from core.testing import client_for, make_alert, make_payload, make_sensor, sha


class AlertApiTests(TestCase):
    def setUp(self):
        self.c = client_for()
        self.s1 = make_sensor("edge", os="LINUX")
        self.s2 = make_sensor("win", os="WINDOWS")
        now = timezone.now()
        make_alert(self.s1, severity="LOW", signature="SSH brute force", signature_id=11, protocol="TCP", source_ip="203.0.113.9", timestamp=now - timedelta(days=3))
        make_alert(self.s1, severity="CRITICAL", signature="Beacon", signature_id=22, protocol="UDP", timestamp=now - timedelta(hours=2))
        make_alert(self.s2, severity="MEDIUM", signature="Macro doc", signature_id=33, protocol="TCP", payload_available=True, payload_hash=sha(7), payload_size=99, timestamp=now - timedelta(hours=1))
        make_alert(self.s2, severity="HIGH", signature="Command injection", signature_id=44, protocol="tcp", timestamp=now - timedelta(minutes=5))

    def ids(self, query=""):
        return [a["signature_id"] for a in self.c.get(f"/api/alerts{query}").json()["results"]]

    def test_list_shape_and_default_order_newest_first(self):
        d = self.c.get("/api/alerts").json()
        self.assertEqual(set(d), {"count", "page", "page_size", "results"})
        self.assertEqual(d["count"], 4)
        self.assertEqual(self.ids(), [44, 33, 22, 11])

    def test_raw_event_is_never_exposed(self):
        a = self.c.get("/api/alerts").json()["results"][0]
        self.assertNotIn("raw_event", a)

    def test_filters(self):
        self.assertEqual(self.ids("?severity=CRITICAL"), [22])
        self.assertEqual(self.ids(f"?sensor={self.s2.pk}"), [44, 33])
        self.assertEqual(sorted(self.ids("?protocol=TCP")), [11, 33, 44])  # case-insensitive
        self.assertEqual(self.ids("?rule=33"), [33])
        self.assertEqual(self.ids("?has_payload=true"), [33])

    def test_date_filters(self):
        frm = (timezone.now() - timedelta(days=1)).isoformat().replace("+00:00", "Z")
        self.assertNotIn(11, self.ids(f"?date_from={frm}"))
        to = (timezone.now() - timedelta(days=1)).isoformat().replace("+00:00", "Z")
        self.assertEqual(self.ids(f"?date_to={to}"), [11])

    def test_search_covers_signature_ip_hash_sensor_and_sid(self):
        self.assertEqual(self.ids("?search=brute"), [11])
        self.assertEqual(self.ids("?search=203.0.113.9"), [11])
        self.assertEqual(self.ids(f"?search={sha(7)[:12]}"), [33])
        self.assertEqual(self.ids("?search=win"), [44, 33])
        self.assertEqual(self.ids("?search=22"), [22])

    def test_search_treats_input_as_data(self):
        self.assertEqual(self.c.get("/api/alerts?search=' OR 1=1 --").json()["count"], 0)
        self.assertEqual(self.c.get("/api/alerts?search=%25").json()["count"], 0)

    def test_severity_sorts_by_rank_not_alphabet(self):
        self.assertEqual(self.ids("?ordering=-severity"), [22, 44, 33, 11])
        self.assertEqual(self.ids("?ordering=severity"), [11, 33, 44, 22])

    def test_other_sorts(self):
        self.assertEqual(self.ids("?ordering=signature"), [22, 44, 33, 11])
        self.assertEqual(self.ids("?ordering=timestamp"), [11, 22, 33, 44])
        self.assertEqual(self.ids("?ordering=-payload")[0], 33)

    def test_invalid_ordering_and_filter_values_are_rejected(self):
        self.assertEqual(self.c.get("/api/alerts?ordering=password").status_code, 400)
        self.assertEqual(self.c.get("/api/alerts?severity=URGENT").status_code, 400)
        self.assertEqual(self.c.get("/api/alerts?sensor=abc").status_code, 400)
        self.assertEqual(self.c.get("/api/alerts?date_from=yesterday").status_code, 400)

    def test_pagination_and_clamping(self):
        d = self.c.get("/api/alerts?page_size=3").json()
        self.assertEqual((len(d["results"]), d["count"], d["page"]), (3, 4, 1))
        d = self.c.get("/api/alerts?page_size=3&page=2").json()
        self.assertEqual(len(d["results"]), 1)
        self.assertEqual(self.c.get("/api/alerts?page_size=3&page=99").json()["page"], 2)  # clamped, not 404
        self.assertEqual(self.c.get("/api/alerts?page=abc").json()["page"], 1)
        self.assertEqual(self.c.get("/api/alerts?page_size=100000").json()["page_size"], 100)

    def test_pages_do_not_overlap_when_sort_key_ties(self):
        same = timezone.now()
        for _ in range(7):
            make_alert(self.s1, timestamp=same, severity="LOW")
        seen = []
        for page in (1, 2, 3):
            seen += [a["id"] for a in self.c.get(f"/api/alerts?ordering=severity&page_size=4&page={page}").json()["results"]]
        self.assertEqual(len(seen), len(set(seen)))

    def test_detail_and_404(self):
        a = Alert.objects.first()
        self.assertEqual(self.c.get(f"/api/alerts/{a.pk}").json()["id"], a.pk)
        self.assertEqual(self.c.get("/api/alerts/999999").status_code, 404)

    def test_missing_optional_fields_come_back_null_not_invented(self):
        a = make_alert(self.s1, source_ip=None, source_port=None, destination_ip=None, destination_port=None, protocol="", priority=None, classification="")
        d = self.c.get(f"/api/alerts/{a.pk}").json()
        for k in ("source_ip", "source_port", "destination_ip", "destination_port", "priority", "payload_hash", "payload_size"):
            self.assertIsNone(d[k], k)
        self.assertFalse(d["payload_available"])


class AlertModelTests(TestCase):
    def test_payload_flag_requires_a_hash(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            make_alert(payload_available=True, payload_hash=None)

    def test_hash_must_be_lowercase_sha256(self):
        a = make_alert(payload_available=True, payload_hash="ABC")
        from django.core.exceptions import ValidationError

        with self.assertRaises(ValidationError):
            a.full_clean()

    def test_payload_link_by_hash(self):
        p = make_payload(5)
        make_alert(payload_available=True, payload_hash=p.sha256)
        self.assertEqual(Alert.objects.filter(payload_hash=p.sha256).count(), 1)
