from datetime import timedelta

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from alerts.models import Alert
from core.testing import batch, event, make_registered_sensor, sensor_client, sha
from payloads.models import Payload

SHA = sha(0xABC)


class IngestBase(TestCase):
    def setUp(self):
        cache.clear()
        self.sensor, self.key = make_registered_sensor("edge")
        self.c = sensor_client(self.key)

    def send(self, *events, **kw):
        return self.c.post("/api/ingest/events", batch(*events), format="json", **kw)


class ValidEventTests(IngestBase):
    def test_full_event_is_stored_with_every_field(self):
        r = self.send(event(payload={"sha256": SHA, "size": 4096, "mime_type": "application/zip", "filename": "a.zip"}))
        self.assertEqual(r.json(), {"received": 1, "accepted": 1, "duplicates": 0, "rejected": 0, "errors": []})
        a = Alert.objects.get()
        self.assertEqual((a.sensor, a.signature_id, a.signature, a.classification, a.priority, a.protocol),
                         (self.sensor, 1000101, "TEST trojan beacon", "trojan-activity", 1, "TCP"))
        self.assertEqual((a.source_ip, a.source_port, a.destination_ip, a.destination_port), ("10.0.0.5", 44321, "203.0.113.9", 80))
        self.assertEqual((a.payload_available, a.payload_hash, a.payload_size), (True, SHA, 4096))

    def test_minimal_event_stores_what_exists_and_invents_nothing(self):
        r = self.send({"timestamp": timezone.now().isoformat(), "signature_id": 7})
        self.assertEqual(r.json()["accepted"], 1)
        a = Alert.objects.get()
        self.assertEqual(a.signature, "SID 1:7")  # label only; no pretend rule text
        self.assertEqual((a.classification, a.protocol), ("", ""))
        for field in ("priority", "source_ip", "source_port", "destination_ip", "destination_port", "payload_hash", "payload_size"):
            self.assertIsNone(getattr(a, field), field)
        self.assertFalse(a.payload_available)
        self.assertEqual(a.severity, "LOW")

    def test_a_sensor_cannot_choose_which_sensor_it_is(self):
        other, _ = make_registered_sensor("someone-else")
        self.send(event(sensor=other.pk, sensor_id=other.pk, sensor_name="someone-else"))
        self.assertEqual(Alert.objects.get().sensor, self.sensor)

    def test_ipv6_addresses_are_normalised(self):
        self.send(event(source_ip="2001:DB8:0:0:0:0:0:1", destination_ip="::1"))
        self.assertEqual(Alert.objects.get().source_ip, "2001:db8::1")

    def test_protocol_is_upper_cased(self):
        self.send(event(protocol="udp"))
        self.assertEqual(Alert.objects.get().protocol, "UDP")

    def test_batch_accepts_many_events(self):
        r = self.send(*[event(pkt_num=i) for i in range(200)])
        self.assertEqual(r.json()["accepted"], 200)
        self.assertEqual(Alert.objects.count(), 200)


class SeverityTests(IngestBase):
    def severity(self, **kw):
        self.send(event(**kw))
        return Alert.objects.latest("id").severity

    def test_mapping(self):
        self.assertEqual(self.severity(priority=1, classification="trojan-activity"), "CRITICAL")
        self.assertEqual(self.severity(priority=1, classification="TROJAN-ACTIVITY", pkt_num=2), "CRITICAL")
        self.assertEqual(self.severity(priority=1, classification="attempted-recon", pkt_num=3), "HIGH")
        self.assertEqual(self.severity(priority=2, pkt_num=4), "MEDIUM")
        self.assertEqual(self.severity(priority=3, pkt_num=5), "LOW")
        self.assertEqual(self.severity(priority=4, pkt_num=6), "LOW")
        self.assertEqual(self.severity(priority=None, pkt_num=7), "LOW")

    @override_settings(SENTINEL_CRITICAL_CLASSIFICATIONS=["web-application-attack"])
    def test_critical_classes_are_configurable(self):
        self.assertEqual(self.severity(priority=1, classification="web-application-attack"), "CRITICAL")
        self.assertEqual(self.severity(priority=1, classification="trojan-activity", pkt_num=2), "HIGH")


class PartialAcceptanceTests(IngestBase):
    def test_valid_events_are_kept_when_others_in_the_batch_are_bad(self):
        r = self.send(event(pkt_num=1), event(signature_id=-1, pkt_num=2), event(pkt_num=3), {"nonsense": True})
        d = r.json()
        self.assertEqual((r.status_code, d["received"], d["accepted"], d["rejected"]), (200, 4, 2, 2))
        self.assertEqual([e["index"] for e in d["errors"]], [1, 3])
        self.assertEqual(Alert.objects.count(), 2)

    def test_error_report_is_capped(self):
        r = self.send(*[{"signature_id": "x"} for _ in range(120)])
        self.assertEqual(r.json()["rejected"], 120)
        self.assertEqual(len(r.json()["errors"]), 50)


class InvalidEventTests(IngestBase):
    def rejected(self, **kw):
        r = self.send(event(**kw))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["rejected"], 1, kw)
        self.assertEqual(Alert.objects.count(), 0, kw)
        return r.json()["errors"][0]["errors"]

    def test_each_bad_field_is_rejected_with_a_reason(self):
        for kw, field in [
            ({"timestamp": "yesterday"}, "timestamp"), ({"timestamp": None}, "timestamp"),
            ({"signature_id": None}, "signature_id"), ({"signature_id": "abc"}, "signature_id"), ({"signature_id": 2**40}, "signature_id"),
            ({"source_ip": "999.1.1.1"}, "source_ip"), ({"destination_ip": "not an ip"}, "destination_ip"),
            ({"source_port": 70000}, "source_port"), ({"destination_port": -1}, "destination_port"),
            ({"priority": 999}, "priority"), ({"protocol": "TCP; DROP TABLE"}, "protocol"), ({"protocol": "x" * 40}, "protocol"),
            ({"pkt_num": -3}, "pkt_num"), ({"signature": ["list"]}, "signature"), ({"raw": "string"}, "raw"),
            ({"payload": {"sha256": "short", "size": 1}}, "payload"), ({"payload": {"sha256": SHA, "size": -1}}, "payload"),
            ({"payload": {"sha256": "g" * 64, "size": 1}}, "payload"), ({"payload": {"size": 1}}, "payload"),
        ]:
            self.assertIn(field, self.rejected(**kw), kw)

    def test_future_timestamps_are_rejected_to_expose_clock_or_timezone_mistakes(self):
        errors = self.rejected(timestamp=(timezone.now() + timedelta(hours=2)).isoformat())
        self.assertIn("future", errors["timestamp"][0])

    def test_small_clock_skew_is_tolerated(self):
        self.assertEqual(self.send(event(timestamp=(timezone.now() + timedelta(seconds=60)).isoformat())).json()["accepted"], 1)

    def test_very_old_events_are_rejected_but_recent_backlog_is_fine(self):
        self.rejected(timestamp=(timezone.now() - timedelta(days=90)).isoformat())
        self.assertEqual(self.send(event(timestamp=(timezone.now() - timedelta(days=3)).isoformat())).json()["accepted"], 1)


class EnvelopeTests(IngestBase):
    def test_malformed_envelopes_are_400_not_500(self):
        for body in ({}, {"schema": 1}, {"schema": 1, "events": []}, {"schema": 1, "events": "x"}, {"schema": 2, "events": [event()]},
                     {"schema": 1, "events": [1, 2]}, {"schema": "one", "events": [event()]}, [event()], "text"):
            r = self.c.post("/api/ingest/events", body, format="json")
            self.assertEqual(r.status_code, 400, body)
        self.assertEqual(Alert.objects.count(), 0)

    def test_invalid_json_is_400(self):
        r = self.c.post("/api/ingest/events", "{not json", content_type="application/json")
        self.assertEqual(r.status_code, 400)

    def test_wrong_content_type_is_415(self):
        r = self.c.post("/api/ingest/events", "x=1", content_type="application/x-www-form-urlencoded")
        self.assertEqual(r.status_code, 415)

    @override_settings(INGEST_MAX_EVENTS_PER_REQUEST=5)
    def test_event_count_limit(self):
        self.assertEqual(self.c.post("/api/ingest/events", batch(*[event(pkt_num=i) for i in range(6)]), format="json").status_code, 400)
        self.assertEqual(self.send(*[event(pkt_num=i) for i in range(5)]).json()["accepted"], 5)


class DuplicateTests(IngestBase):
    def test_resending_an_event_never_creates_a_second_alert(self):
        e = event()
        self.assertEqual(self.send(e).json()["accepted"], 1)
        d = self.send(e).json()
        self.assertEqual((d["accepted"], d["duplicates"]), (0, 1))
        self.assertEqual(Alert.objects.count(), 1)

    def test_duplicates_inside_one_batch_are_collapsed(self):
        e = event()
        d = self.send(e, e, e).json()
        self.assertEqual((d["accepted"], d["duplicates"]), (1, 2))

    def test_events_differing_in_packet_number_are_distinct(self):
        self.assertEqual(self.send(event(pkt_num=1), event(pkt_num=2)).json()["accepted"], 2)

    def test_the_same_event_from_two_sensors_is_stored_twice(self):
        _, other_key = make_registered_sensor("second")
        e = event()
        self.send(e)
        sensor_client(other_key).post("/api/ingest/events", batch(e), format="json")
        self.assertEqual(Alert.objects.count(), 2)

    def test_collector_supplied_fields_cannot_forge_an_event_id(self):
        self.send(event(event_id="x" * 64))
        self.assertNotEqual(Alert.objects.get().event_id, "x" * 64)


class PayloadMetadataTests(IngestBase):
    def meta(self, **kw):
        return {"sha256": SHA, "size": 1000, "mime_type": "application/zip", **kw}

    def test_new_payload_starts_unknown_with_no_virustotal_data(self):
        self.send(event(payload=self.meta()))
        p = Payload.objects.get()
        self.assertEqual((p.status, p.vt_total, p.vt_malicious, p.vt_last_checked), ("UNKNOWN", None, None, None))
        self.assertEqual((p.sensor, p.size, p.signature_id), (self.sensor, 1000, 1000101))

    def test_hash_is_normalised_to_lower_case(self):
        self.send(event(payload=self.meta(sha256=SHA.upper())))
        self.assertEqual(Payload.objects.get().sha256, SHA)

    def test_repeat_sightings_widen_first_and_last_seen_and_count_alerts(self):
        t0 = timezone.now() - timedelta(hours=5)
        t1 = timezone.now() - timedelta(hours=1)
        self.send(event(timestamp=t1.isoformat(), pkt_num=1, payload=self.meta()))
        self.send(event(timestamp=t0.isoformat(), pkt_num=2, payload=self.meta()))
        p = Payload.objects.get()
        self.assertEqual(Payload.objects.count(), 1)
        self.assertEqual((p.first_seen, p.last_seen), (t0, t1))
        self.assertEqual(Alert.objects.filter(payload_hash=SHA).count(), 2)

    def test_same_hash_with_a_different_size_is_refused(self):
        self.send(event(pkt_num=1, payload=self.meta(size=1000)))
        d = self.send(event(pkt_num=2, payload=self.meta(size=999))).json()
        self.assertEqual((d["accepted"], d["rejected"]), (0, 1))
        self.assertEqual(Payload.objects.get().size, 1000)

    def test_conflict_inside_one_batch_is_also_refused(self):
        d = self.send(event(pkt_num=1, payload=self.meta(size=10)), event(pkt_num=2, payload=self.meta(size=11))).json()
        self.assertEqual((d["accepted"], d["rejected"]), (1, 1))

    def test_existing_status_and_virustotal_result_are_never_overwritten_by_ingestion(self):
        self.send(event(pkt_num=1, payload=self.meta()))
        Payload.objects.update(status="MALICIOUS", vt_malicious=40, vt_total=70)
        self.send(event(pkt_num=2, payload=self.meta()))
        p = Payload.objects.get()
        self.assertEqual((p.status, p.vt_malicious, p.vt_total), ("MALICIOUS", 40, 70))

    def test_events_without_payload_never_create_one(self):
        self.send(event())
        self.assertEqual(Payload.objects.count(), 0)

    def test_filename_is_reduced_to_a_basename(self):
        for bad, pkt in (("../../etc/passwd", 1), ("C:\\Windows\\evil.exe", 2), ("..", 3)):
            Payload.objects.all().delete()
            self.send(event(pkt_num=pkt, payload=self.meta(filename=bad)))
            self.assertNotIn("/", Payload.objects.get().filename or "")
            self.assertNotIn("\\", Payload.objects.get().filename or "")
        self.assertEqual(Payload.objects.get().filename, None)


class SanitisationTests(IngestBase):
    def test_control_and_bidi_characters_are_stripped_from_text(self):
        self.send(event(signature="evil\x00rule\u202eexe.txt\nline2\u200b", classification="a\x07b"))
        a = Alert.objects.get()
        self.assertEqual(a.signature, "evilruleexe.txt line2")
        self.assertEqual(a.classification, "ab")

    def test_overlong_text_is_truncated_not_rejected(self):
        self.send(event(signature="x" * 1000, classification="y" * 300))
        a = Alert.objects.get()
        self.assertEqual((len(a.signature), len(a.classification)), (512, 128))

    def test_markup_is_stored_as_inert_text(self):
        self.send(event(signature="<script>alert(1)</script>"))
        self.assertEqual(Alert.objects.get().signature, "<script>alert(1)</script>")  # React renders text; nothing is ever injected as HTML

    def test_packet_bytes_are_never_persisted_even_if_sent(self):
        self.send(event(raw={"b64_data": "QUJD" * 100, "proto": "TCP"}))
        self.assertEqual(Alert.objects.get().raw_event, {"proto": "TCP"})

    @override_settings(INGEST_MAX_RAW_BYTES=100)
    def test_oversized_raw_event_is_replaced_by_a_marker(self):
        self.send(event(raw={"blob": "z" * 500}))
        self.assertTrue(Alert.objects.get().raw_event["truncated"])

    def test_raw_event_is_not_exposed_by_the_read_api(self):
        from core.testing import client_for

        self.send(event(raw={"secret_field": 1}))
        self.assertNotIn("raw_event", client_for().get("/api/alerts").json()["results"][0])


class SensorHealthFromIngestTests(IngestBase):
    def test_any_authenticated_request_marks_the_sensor_alive_using_the_servers_clock(self):
        self.assertIsNone(self.sensor.last_seen)
        self.send(event(timestamp=(timezone.now() - timedelta(days=2)).isoformat()))  # old event, fresh heartbeat
        self.sensor.refresh_from_db()
        self.assertLess((timezone.now() - self.sensor.last_seen).total_seconds(), 5)
        self.assertEqual(self.sensor.status, "ONLINE")

    def test_a_fully_rejected_batch_still_counts_as_a_sign_of_life(self):
        self.send({"signature_id": "bad"})
        self.sensor.refresh_from_db()
        self.assertIsNotNone(self.sensor.last_seen)

    def test_heartbeat_updates_details_but_only_those_provided(self):
        self.sensor.snort_version = "3.1.0.0"
        self.sensor.hostname = "old"
        self.sensor.save()
        r = self.c.post("/api/ingest/heartbeat", {"hostname": "edge01", "os": "WINDOWS", "collector_version": "0.1.0"}, format="json")
        self.assertEqual(r.status_code, 200)
        self.sensor.refresh_from_db()
        self.assertEqual((self.sensor.hostname, self.sensor.os, self.sensor.collector_version, self.sensor.snort_version),
                         ("edge01", "WINDOWS", "0.1.0", "3.1.0.0"))
        self.assertEqual(self.sensor.status, "ONLINE")

    def test_heartbeat_rejects_unknown_os_and_bad_ip(self):
        self.assertEqual(self.c.post("/api/ingest/heartbeat", {"os": "BSD"}, format="json").status_code, 400)
        self.assertEqual(self.c.post("/api/ingest/heartbeat", {"ip": "nope"}, format="json").status_code, 400)

    def test_empty_heartbeat_is_valid_and_just_proves_life(self):
        self.assertEqual(self.c.post("/api/ingest/heartbeat", {}, format="json").status_code, 200)
        self.sensor.refresh_from_db()
        self.assertIsNotNone(self.sensor.last_seen)

    def test_status_decays_without_further_contact(self):
        self.send(event())
        self.sensor.last_seen = timezone.now() - timedelta(minutes=3)
        self.sensor.save()
        self.assertEqual(self.sensor.status, "WARNING")
        self.sensor.last_seen = timezone.now() - timedelta(minutes=15)
        self.sensor.save()
        self.assertEqual(self.sensor.status, "OFFLINE")


class EndToEndReadBackTests(IngestBase):
    def test_ingested_data_appears_in_the_dashboard_api_and_statistics(self):
        from core.testing import client_for

        self.send(event(pkt_num=1, priority=1, classification="trojan-activity", payload={"sha256": SHA, "size": 5, "mime_type": "x/y"}),
                  event(pkt_num=2, priority=3, classification="misc-activity", protocol="UDP"))
        viewer = client_for()
        stats = viewer.get("/api/dashboard/stats").json()
        self.assertEqual((stats["total_alerts"], stats["by_severity"]["CRITICAL"], stats["by_severity"]["LOW"], stats["total_payloads"]), (2, 1, 1, 1))
        self.assertEqual(viewer.get(f"/api/payloads/{SHA}").json()["alert_count"], 1)
        self.assertEqual({p["protocol"] for p in viewer.get("/api/dashboard/protocols").json()}, {"TCP", "UDP"})
        sensors = {s["name"]: s for s in viewer.get("/api/sensors").json()}
        self.assertEqual(sensors["edge"]["status"], "ONLINE")
