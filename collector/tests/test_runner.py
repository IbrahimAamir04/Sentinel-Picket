import json
import logging
import tempfile
import threading
import unittest
from pathlib import Path

from sentinel_collector.client import Response, TransientError
from sentinel_collector.config import Config
from sentinel_collector.runner import Runner, Shutdown
from sentinel_collector.state import StateStore
from sentinel_collector.tailer import Tailer

logging.disable(logging.CRITICAL)


def line(i, **kw):
    return json.dumps({"seconds": 1759492800 + i, "rule": f"1:{1000 + i}:1", "msg": f"m{i}", "priority": 2, "pkt_num": i, **kw})


class FakeClient:
    """Plays back a script of outcomes: a Response, or an exception instance to raise."""

    def __init__(self, *script):
        self.script, self.sent, self.heartbeats = list(script), [], 0

    def send_events(self, events):
        self.sent.append(events)
        step = self.script.pop(0) if self.script else Response(200, {"accepted": len(events), "duplicates": 0, "rejected": 0})
        if isinstance(step, Exception):
            raise step
        return step

    def heartbeat(self, info):
        self.heartbeats += 1
        return Response(200, {})


OK = lambda n=1: Response(200, {"accepted": n, "duplicates": 0, "rejected": 0})


class RunnerCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / "alert_json.txt"
        self.cfg = Config(url="http://127.0.0.1:1", api_key="k", alert_file=str(self.path), state_file=str(Path(self.dir.name) / "st.json"),
                          timezone="UTC", batch_size=3)
        self.state = StateStore(self.cfg.state_file, self.cfg.alert_file)
        self.stop = threading.Event()
        self.sleeps = []

    def tearDown(self):
        self.dir.cleanup()

    def lines(self, *items):
        with open(self.path, "a") as f:
            for i in items:
                f.write((i if isinstance(i, str) else line(i)) + "\n")

    def runner(self, client):
        t = Tailer(str(self.path), "beginning", 1_000_000, self.state.load())
        self.sleeps = []
        return Runner(self.cfg, client, t, self.state, self.stop, sleep=lambda s: self.sleeps.append(s))

    def sent_sids(self, client):
        return [e["signature_id"] for batch in client.sent for e in batch]


class DeliveryTests(RunnerCase):
    def test_events_are_sent_in_batches_of_the_configured_size(self):
        self.lines(*range(7))
        c = FakeClient()
        self.runner(c).step()
        self.assertEqual([len(b) for b in c.sent], [3, 3, 1])
        self.assertEqual(self.sent_sids(c), [1000 + i for i in range(7)])

    def test_position_is_saved_only_after_delivery(self):
        self.lines(0, 1)
        c = FakeClient()
        r = self.runner(c)
        r.step()
        self.assertEqual(self.state.load().offset, self.path.stat().st_size)

    def test_no_new_lines_means_no_request(self):
        c = FakeClient()
        self.lines(0)
        r = self.runner(c)
        r.step()
        r.step()
        self.assertEqual(len(c.sent), 1)

    def test_skipped_lines_do_not_block_valid_ones(self):
        self.lines(0, "garbage", '{"no":"rule"}', 1)
        c = FakeClient()
        r = self.runner(c)
        r.step()
        self.assertEqual(self.sent_sids(c), [1000, 1001])
        self.assertEqual(r.stats["skipped"], 2)


class FailureTests(RunnerCase):
    def test_network_outage_retries_then_succeeds_without_losing_events(self):
        self.lines(0, 1)
        c = FakeClient(TransientError("refused"), TransientError("refused"), OK(2))
        r = self.runner(c)
        r.step()
        self.assertEqual(len(c.sent), 3)  # same batch each time
        self.assertEqual(c.sent[0], c.sent[2])
        self.assertEqual(len(self.sleeps), 2)
        self.assertTrue(all(s > 0 for s in self.sleeps))

    def test_server_errors_are_retried(self):
        self.lines(0)
        for status in (500, 502, 503, 429, 408, 409):
            c = FakeClient(Response(status, {"detail": "x"}), OK())
            self.state.path.unlink(missing_ok=True)
            self.path.unlink(missing_ok=True)
            self.lines(0)
            self.runner(c).step()
            self.assertEqual(len(c.sent), 2, status)

    def test_retry_after_is_honoured(self):
        self.lines(0)
        c = FakeClient(Response(429, {}, retry_after=30), OK())
        self.runner(c).step()
        self.assertGreaterEqual(self.sleeps[0], 30)

    def test_backoff_grows_and_is_capped(self):
        self.lines(0)
        c = FakeClient(*[TransientError("x")] * 12, OK())
        self.runner(c).step()
        self.assertLessEqual(max(self.sleeps), 61)
        self.assertGreater(self.sleeps[5], self.sleeps[0])

    def test_wrong_api_key_keeps_events_and_keeps_trying(self):
        self.lines(0)
        c = FakeClient(Response(401, {"detail": "bad"}), Response(401, {"detail": "bad"}), OK())
        r = self.runner(c)
        r.step()
        self.assertEqual(len(c.sent), 3)
        self.assertEqual(r.stats["dropped"], 0)

    def test_a_definitive_refusal_drops_the_batch_so_it_cannot_block_the_queue_forever(self):
        self.lines(0, 1, 2, 3)
        c = FakeClient(Response(400, {"detail": "malformed"}), OK())
        r = self.runner(c)
        r.step()
        self.assertEqual(r.stats["dropped"], 3)
        self.assertEqual(self.state.load().offset, self.path.stat().st_size)  # moved past it
        self.assertEqual(self.sent_sids(c)[-1], 1003)

    def test_too_large_batches_are_halved(self):
        self.lines(0, 1, 2)
        c = FakeClient(Response(413, {}), OK(1), OK(2))
        r = self.runner(c)
        r.step()
        self.assertEqual([len(b) for b in c.sent], [3, 1, 2])
        self.assertEqual(r.stats["dropped"], 0)

    def test_a_single_oversized_event_is_dropped_not_looped(self):
        self.lines(0)
        c = FakeClient(Response(413, {}))
        r = self.runner(c)
        r.step()
        self.assertEqual((len(c.sent), r.stats["dropped"]), (1, 1))

    def test_server_side_rejections_are_counted_but_do_not_stall(self):
        self.lines(0, 1)
        c = FakeClient(Response(200, {"accepted": 1, "duplicates": 0, "rejected": 1, "errors": [{"index": 1, "errors": {"x": ["y"]}}]}))
        r = self.runner(c)
        r.step()
        self.assertEqual((r.stats["accepted"], r.stats["rejected"]), (1, 1))


class ShutdownAndRestartTests(RunnerCase):
    def test_stopping_during_an_outage_leaves_the_position_unsaved(self):
        self.lines(0, 1)
        c = FakeClient(*[TransientError("down")] * 50)
        r = self.runner(c)
        r._sleep = lambda s: self.stop.set()
        with self.assertRaises(Shutdown):
            r.step()
        self.assertIsNone(self.state.load())  # nothing was marked as delivered

    def test_after_a_crash_the_undelivered_events_are_sent_again_on_restart(self):
        self.lines(0, 1, 2)
        c1 = FakeClient(*[TransientError("down")] * 5)
        r1 = self.runner(c1)
        r1._sleep = lambda s: self.stop.set()
        with self.assertRaises(Shutdown):
            r1.step()
        self.stop.clear()
        c2 = FakeClient()
        self.runner(c2).step()  # a fresh process reading the saved (absent) state
        self.assertEqual(self.sent_sids(c2), [1000, 1001, 1002])

    def test_restart_after_success_sends_only_new_events(self):
        self.lines(0, 1)
        self.runner(FakeClient()).step()
        self.lines(2)
        c = FakeClient()
        self.runner(c).step()
        self.assertEqual(self.sent_sids(c), [1002])

    def test_run_forever_sends_a_heartbeat_even_when_there_are_no_alerts(self):
        self.lines()
        c = FakeClient()
        r = self.runner(c)
        calls = []
        r._sleep = lambda s: (calls.append(s), self.stop.set())
        r.run_forever()
        self.assertEqual(c.heartbeats, 1)
        self.assertEqual(c.sent, [])


class PayloadPrivacyTests(RunnerCase):
    def test_packet_bytes_never_leave_the_sensor(self):
        import base64

        secret = base64.b64encode(b"MZ" + b"TOPSECRETPACKETBYTES" * 10).decode()
        self.lines(line(0, b64_data=secret))
        self.cfg = Config(**{**self.cfg.__dict__, "payloads_enabled": True})
        c = FakeClient()
        self.runner(c).step()
        wire = json.dumps(c.sent)
        self.assertNotIn(secret, wire)
        self.assertNotIn("b64_data", wire)
        self.assertNotIn("TOPSECRET", wire)
        self.assertEqual(set(c.sent[0][0]["payload"]), {"sha256", "size", "mime_type"})


if __name__ == "__main__":
    unittest.main()
