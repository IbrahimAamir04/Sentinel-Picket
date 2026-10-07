import json
import unittest
from datetime import datetime, timezone

from sentinel_collector import snort
from sentinel_collector.snort import SkipEvent

NOW = datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc)
KW = dict(tz_name="UTC", payloads_enabled=False, payload_min_bytes=16, payload_max_b64_chars=10_000, now=NOW)


def norm(ev, **over):
    return snort.normalize(ev, **{**KW, **over})


class RuleTests(unittest.TestCase):
    def test_gid_sid_rev(self):
        self.assertEqual(snort.parse_rule("1:1000001:3"), (1, 1000001, 3))

    def test_malformed_rules(self):
        for bad in (None, "", "1:2", "a:b:c", "1:2:3:4", 12345, ["1:2:3"]):
            self.assertEqual(snort.parse_rule(bad), (None, None, None), bad)

    def test_explicit_fields_win_over_rule_string(self):
        e = norm({"seconds": 1759492800, "rule": "1:5:1", "sid": 9, "gid": 3, "rev": 4})
        self.assertEqual((e["signature_id"], e["gid"], e["rev"]), (9, 3, 4))

    def test_line_without_a_rule_is_skipped_not_invented(self):
        with self.assertRaises(SkipEvent):
            norm({"seconds": 1759492800, "proto": "TCP"})


class TimestampTests(unittest.TestCase):
    def ts(self, ev, tz="UTC"):
        return snort.parse_timestamp(ev, tz, NOW)

    def test_seconds_is_preferred_and_unambiguous(self):
        self.assertEqual(self.ts({"seconds": 1759492800, "timestamp": "01/01-00:00:00.000000"}), datetime(2025, 10, 3, 12, 0, tzinfo=timezone.utc))

    def test_seconds_as_string_or_float(self):
        want = datetime.fromtimestamp(1759492800.5, tz=timezone.utc)
        self.assertEqual(self.ts({"seconds": "1759492800.5"}), want)
        self.assertEqual(self.ts({"seconds": 1759492800.5}), want)

    def test_snort3_default_text_form_without_year(self):
        self.assertEqual(self.ts({"timestamp": "10/03-11:59:30.250000"}), datetime(2026, 10, 3, 11, 59, 30, 250000, tzinfo=timezone.utc))

    def test_year_is_inferred_as_most_recent_not_in_the_future(self):
        # 12/31 seen on Jan 2 must be last year; 10/03 seen on 10/03 stays this year.
        jan = datetime(2026, 1, 2, tzinfo=timezone.utc)
        self.assertEqual(snort.parse_timestamp({"timestamp": "12/31-23:00:00.000000"}, "UTC", jan).year, 2025)
        self.assertEqual(snort.parse_timestamp({"timestamp": "01/01-23:00:00.000000"}, "UTC", jan).year, 2026)

    def test_leap_day(self):
        feb = datetime(2028, 3, 1, tzinfo=timezone.utc)
        self.assertEqual(snort.parse_timestamp({"timestamp": "02/29-10:00:00.000000"}, "UTC", feb).day, 29)

    def test_timestamp_with_year(self):
        self.assertEqual(self.ts({"timestamp": "10/03/26-11:00:00.000000"}).year, 2026)

    def test_configured_zone_is_applied(self):
        got = snort.parse_timestamp({"timestamp": "10/03-12:00:00.000000"}, "Asia/Karachi", NOW)
        self.assertEqual(got, datetime(2026, 10, 3, 7, 0, tzinfo=timezone.utc))

    def test_local_zone_uses_the_system_zone(self):
        got = snort.parse_timestamp({"timestamp": "10/03-12:00:00.000000"}, "local", NOW)
        self.assertEqual(got, datetime(2026, 10, 3, 12, 0).astimezone().astimezone(timezone.utc))

    def test_iso_and_epoch_courtesy_forms(self):
        self.assertEqual(self.ts({"timestamp": "2026-10-03T11:00:00Z"}), datetime(2026, 10, 3, 11, 0, tzinfo=timezone.utc))
        self.assertEqual(self.ts({"timestamp": 1759492800}), datetime(2025, 10, 3, 12, 0, tzinfo=timezone.utc))

    def test_unusable_timestamps_are_skipped(self):
        for bad in ({}, {"timestamp": ""}, {"timestamp": "yesterday"}, {"timestamp": "13/45-99:99:99"}, {"timestamp": None}, {"timestamp": True}, {"timestamp": ["x"]}):
            with self.assertRaises(SkipEvent, msg=bad):
                self.ts(bad)

    def test_garbage_seconds_falls_back_to_the_text_timestamp(self):
        self.assertEqual(self.ts({"seconds": "soon", "timestamp": "10/03-11:00:00.000000"}).hour, 11)


class AddressTests(unittest.TestCase):
    def test_ipv4_ap(self):
        self.assertEqual(snort.split_ap("10.0.0.5:44321"), ("10.0.0.5", 44321))

    def test_bare_ip_and_zero_port(self):
        self.assertEqual(snort.split_ap("10.0.0.5"), ("10.0.0.5", None))
        self.assertEqual(snort.split_ap("10.0.0.5:0"), ("10.0.0.5", None))

    def test_ipv6_forms(self):
        self.assertEqual(snort.split_ap("[2001:db8::1]:443"), ("2001:db8::1", 443))
        self.assertEqual(snort.split_ap("[2001:db8::1]"), ("2001:db8::1", None))
        self.assertEqual(snort.split_ap("2001:db8::1"), ("2001:db8::1", None))
        self.assertEqual(snort.split_ap("::1"), ("::1", None))

    def test_garbage_gives_nothing(self):
        for bad in (None, "", "not-an-ip:80", "999.1.1.1:80", ":80", 12, "[garbage]:80", "a:b:c:d"):
            self.assertEqual(snort.split_ap(bad), (None, None), bad)  # never a port without an address
        for bad_port in ("10.0.0.5:99999", "10.0.0.5:abc", "10.0.0.5:-1"):
            self.assertEqual(snort.split_ap(bad_port), ("10.0.0.5", None), bad_port)  # a good address survives a bad port

    def test_explicit_addr_and_port_fields_are_preferred_over_ap(self):
        e = norm({"seconds": 1759492800, "sid": 1, "src_addr": "10.1.1.1", "src_port": 5, "src_ap": "9.9.9.9:9"})
        self.assertEqual((e["source_ip"], e["source_port"]), ("10.1.1.1", 5))

    def test_malformed_address_is_dropped_but_the_alert_survives(self):
        e = norm({"seconds": 1759492800, "sid": 1, "src_addr": "garbage", "dst_ap": "10.0.0.9:80"})
        self.assertNotIn("source_ip", e)
        self.assertEqual((e["destination_ip"], e["destination_port"]), ("10.0.0.9", 80))


class NormalizeTests(unittest.TestCase):
    FULL = {"seconds": 1759492800, "timestamp": "10/03-12:00:00.000000", "pkt_num": 7, "proto": "tcp", "dir": "C2S",
            "src_addr": "10.0.0.5", "src_port": 44321, "dst_addr": "203.0.113.9", "dst_port": 80,
            "rule": "1:1000101:2", "msg": "TEST beacon", "class": "trojan-activity", "priority": 1, "action": "allow"}

    def test_full_event(self):
        e = norm(self.FULL)
        for k, v in {"signature_id": 1000101, "gid": 1, "rev": 2, "signature": "TEST beacon", "classification": "trojan-activity",
                     "priority": 1, "protocol": "TCP", "source_ip": "10.0.0.5", "source_port": 44321, "destination_ip": "203.0.113.9",
                     "destination_port": 80, "pkt_num": 7, "timestamp": "2025-10-03T12:00:00Z"}.items():
            self.assertEqual(e[k], v, k)

    def test_minimal_event_contains_only_what_was_present(self):
        e = norm({"seconds": 1759492800, "rule": "1:5:1"})
        self.assertEqual(set(e) - {"raw"}, {"timestamp", "signature_id", "gid", "rev"})

    def test_original_event_is_kept_as_raw_without_packet_bytes(self):
        e = norm({**self.FULL, "b64_data": "QUJD"})
        self.assertNotIn("b64_data", e["raw"])
        self.assertEqual(e["raw"]["action"], "allow")

    def test_huge_raw_is_replaced_by_a_marker(self):
        self.assertEqual(norm({**self.FULL, "blob": "x" * 20000})["raw"], {"truncated": True})

    def test_bad_priority_and_non_string_text_become_absent(self):
        e = norm({**self.FULL, "priority": "high", "msg": 5, "class": ["x"]})
        for k in ("priority", "signature", "classification"):
            self.assertNotIn(k, e)

    def test_payload_only_when_enabled_and_present(self):
        import base64
        b64 = base64.b64encode(b"MZ" + b"A" * 100).decode()
        self.assertNotIn("payload", norm({**self.FULL, "b64_data": b64}))
        self.assertIn("payload", norm({**self.FULL, "b64_data": b64}, payloads_enabled=True))
        self.assertNotIn("payload", norm(self.FULL, payloads_enabled=True))

    def test_output_is_json_serialisable(self):
        json.dumps(norm(self.FULL))

    def test_snort2_alert_fast_line_is_normalised(self):
        line = ("10/03-11:59:30.250000  [**] [1:1000001:1] Snort 2 test alert [**] "
                "[Classification: Attempted Information Leak] [Priority: 1] {TCP} "
                "192.0.2.1:54321 -> 198.51.100.2:80")
        event = norm(snort.parse_line(line))
        self.assertEqual(event["timestamp"], "2026-10-03T11:59:30.250000Z")
        self.assertEqual((event["signature_id"], event["gid"], event["rev"]), (1000001, 1, 1))
        self.assertEqual(event["signature"], "Snort 2 test alert")
        self.assertEqual(event["classification"], "Attempted Information Leak")
        self.assertEqual(event["priority"], 1)
        self.assertEqual(event["protocol"], "TCP")
        self.assertEqual((event["source_ip"], event["source_port"]), ("192.0.2.1", 54321))
        self.assertEqual((event["destination_ip"], event["destination_port"]), ("198.51.100.2", 80))

    def test_snort2_alert_fast_without_classification_or_ports(self):
        line = ("10/03-11:59:30.250000 [**] [1:1000001:1] ICMP test [**] "
                "[Priority: 0] {ICMP} 192.0.2.1 -> 198.51.100.2")
        event = norm(snort.parse_line(line))
        self.assertEqual(event["protocol"], "ICMP")
        self.assertEqual((event["source_ip"], event["destination_ip"]), ("192.0.2.1", "198.51.100.2"))
        self.assertEqual(event["priority"], 0)
        self.assertNotIn("classification", event)


class ParseLineTests(unittest.TestCase):
    def test_bad_lines(self):
        for bad in ("", "not json", "{broken", "[1,2]", "42", '"str"', "null"):
            with self.assertRaises(SkipEvent, msg=bad):
                snort.parse_line(bad)

    def test_good_line(self):
        self.assertEqual(snort.parse_line('{"a":1}'), {"a": 1})

    def test_snort2_fast_alert_line(self):
        event = snort.parse_line(
            "10/03-11:59:30.250000 [**] [1:1000001:1] Alert [**] [Priority: 1] "
            "{TCP} 192.0.2.1:1234 -> 198.51.100.2:80"
        )
        self.assertEqual((event["gid"], event["sid"], event["rev"]), (1, 1000001, 1))
        self.assertEqual(event["src_ap"], "192.0.2.1:1234")

    def test_unrecognized_text_is_skipped(self):
        with self.assertRaises(SkipEvent):
            snort.parse_line("Snort started")


if __name__ == "__main__":
    unittest.main()
