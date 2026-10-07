import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from sentinel_collector.client import Client, TransientError, classify
from sentinel_collector.config import Config

KEY = "snt_TESTKEYTESTKEYTESTKEYTESTKEYTESTKEYTESTKEY1"


class Handler(BaseHTTPRequestHandler):
    seen: list = []
    script = {"status": 200, "body": {"accepted": 1}, "headers": {}}

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        Handler.seen.append({"path": self.path, "auth": self.headers.get("Authorization"), "ctype": self.headers.get("Content-Type"),
                             "ua": self.headers.get("User-Agent"), "body": json.loads(self.rfile.read(length) or b"{}"), "host": self.headers.get("Host")})
        s = Handler.script
        self.send_response(s["status"])
        for k, v in s["headers"].items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(s["body"]).encode())

    def log_message(self, *a):
        pass


def cfg(port, **kw):
    return Config(url=f"http://127.0.0.1:{port}", api_key=KEY, alert_file="x", state_file="y", **kw)


class ClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        Handler.seen = []
        Handler.script = {"status": 200, "body": {"accepted": 1}, "headers": {}}
        self.client = Client(cfg(self.port))

    def test_request_shape_and_credentials(self):
        r = self.client.send_events([{"signature_id": 1}])
        self.assertEqual((r.status, r.body), (200, {"accepted": 1}))
        seen = Handler.seen[0]
        self.assertEqual(seen["path"], "/api/ingest/events")
        self.assertEqual(seen["auth"], f"Bearer {KEY}")
        self.assertEqual(seen["body"], {"schema": 1, "events": [{"signature_id": 1}]})
        self.assertTrue(seen["ua"].startswith("sentinel-collector/"))

    def test_heartbeat_endpoint(self):
        self.client.heartbeat({"collector_version": "x"})
        self.assertEqual(Handler.seen[0]["path"], "/api/ingest/heartbeat")

    def test_http_errors_are_returned_not_raised(self):
        Handler.script = {"status": 400, "body": {"detail": "bad"}, "headers": {}}
        r = self.client.send_events([{}])
        self.assertEqual((r.status, r.body["detail"]), (400, "bad"))

    def test_retry_after_is_parsed(self):
        Handler.script = {"status": 429, "body": {}, "headers": {"Retry-After": "7"}}
        self.assertEqual(self.client.send_events([{}]).retry_after, 7.0)

    def test_redirects_are_never_followed_so_the_key_cannot_leak(self):
        Handler.script = {"status": 302, "body": {}, "headers": {"Location": f"http://127.0.0.1:{self.port}/elsewhere"}}
        r = self.client.send_events([{}])
        self.assertEqual(r.status, 302)
        self.assertEqual(len(Handler.seen), 1)  # no second request, so no Authorization header sent anywhere else
        self.assertEqual(classify(302), "drop")

    def test_connection_refused_is_a_transient_error(self):
        dead = Client(cfg(1))  # nothing listens on port 1
        with self.assertRaises(TransientError):
            dead.send_events([{}])

    def test_transient_error_message_never_contains_the_key(self):
        try:
            Client(cfg(1)).send_events([{}])
        except TransientError as e:
            self.assertNotIn(KEY, str(e))

    def test_non_json_error_pages_do_not_crash_the_client(self):
        Handler.script = {"status": 502, "body": "<html>bad gateway</html>", "headers": {}}
        self.assertEqual(self.client.send_events([{}]).status, 502)

    def test_config_repr_hides_the_key(self):
        self.assertNotIn(KEY, repr(cfg(self.port)))


class ClassifyTests(unittest.TestCase):
    def test_table(self):
        for status, kind in [(200, "ok"), (204, "ok"), (400, "drop"), (404, "drop"), (415, "drop"), (302, "drop"), (401, "auth"), (403, "auth"),
                             (408, "retry"), (409, "retry"), (429, "retry"), (500, "retry"), (503, "retry"), (413, "split")]:
            self.assertEqual(classify(status), kind, status)


if __name__ == "__main__":
    unittest.main()
