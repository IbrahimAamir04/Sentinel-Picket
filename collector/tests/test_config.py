import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sentinel_collector.config import ConfigError, load

BASE = """
[server]
url = "{url}"
{server_extra}
[snort]
alert_file = "/var/log/snort/alert_json.txt"
{snort_extra}
[collector]
state_file = "/var/lib/sentinel-collector/state.json"
{collector_extra}
"""


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"SENTINEL_API_KEY": "snt_fromenv"}, clear=False)
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.dir.cleanup()

    def cfg(self, url="https://sentinel.example.com", server_extra="", snort_extra="", collector_extra="", payloads=""):
        p = Path(self.dir.name) / "c.toml"
        p.write_text(BASE.format(url=url, server_extra=server_extra, snort_extra=snort_extra, collector_extra=collector_extra) + payloads)
        return load(p)

    def test_valid_config_with_defaults(self):
        c = self.cfg()
        self.assertEqual((c.url, c.start_at, c.batch_size, c.payloads_enabled), ("https://sentinel.example.com", "end", 100, False))

    def test_payload_hashing_is_opt_in(self):
        self.assertFalse(self.cfg().payloads_enabled)
        self.assertTrue(self.cfg(payloads="\n[payloads]\nenabled = true\n").payloads_enabled)

    def test_key_from_environment_and_never_in_repr(self):
        c = self.cfg()
        self.assertEqual(c.api_key, "snt_fromenv")
        self.assertNotIn("snt_fromenv", repr(c))

    def test_custom_environment_variable_name(self):
        with mock.patch.dict(os.environ, {"MY_KEY": "snt_custom"}):
            self.assertEqual(self.cfg(server_extra='api_key_env = "MY_KEY"').api_key, "snt_custom")

    def test_key_from_file(self):
        with mock.patch.dict(os.environ, {"SENTINEL_API_KEY": ""}):
            kf = Path(self.dir.name) / "key"
            kf.write_text("snt_fromfile\n")
            kf.chmod(0o600)
            self.assertEqual(self.cfg(server_extra=f"api_key_file = {json.dumps(str(kf))}").api_key, "snt_fromfile")

    @unittest.skipIf(sys.platform == "win32", "POSIX permissions")
    def test_world_readable_key_file_triggers_a_warning(self):
        with mock.patch.dict(os.environ, {"SENTINEL_API_KEY": ""}):
            kf = Path(self.dir.name) / "key"
            kf.write_text("snt_fromfile")
            kf.chmod(0o644)
            with mock.patch("sys.stderr") as err:
                self.cfg(server_extra=f"api_key_file = {json.dumps(str(kf))}")
            self.assertIn("chmod 600", "".join(c.args[0] for c in err.write.call_args_list))

    def test_missing_key_is_a_clear_error(self):
        with mock.patch.dict(os.environ, {"SENTINEL_API_KEY": ""}), self.assertRaises(ConfigError) as cm:
            self.cfg()
        self.assertIn("SENTINEL_API_KEY", str(cm.exception))

    def test_a_key_written_into_the_config_file_is_refused(self):
        with self.assertRaises(ConfigError) as cm:
            self.cfg(server_extra='api_key = "snt_oops"')
        self.assertNotIn("snt_oops", str(cm.exception))

    def test_plain_http_to_a_remote_host_is_refused_unless_explicitly_allowed(self):
        with self.assertRaises(ConfigError):
            self.cfg(url="http://sentinel.example.com")
        self.assertEqual(self.cfg(url="http://sentinel.example.com", server_extra="allow_insecure_http = true").url, "http://sentinel.example.com")

    def test_plain_http_to_loopback_is_fine(self):
        for url in ("http://localhost:8000", "http://127.0.0.1:8000"):
            self.assertEqual(self.cfg(url=url).url, url)

    def test_trailing_slash_is_removed(self):
        self.assertEqual(self.cfg(url="https://x.example/").url, "https://x.example")

    def test_bad_values_are_rejected(self):
        for kwargs in ({"url": "ftp://x"}, {"url": "not a url"}, {"url": ""}, {"snort_extra": 'start_at = "middle"'},
                       {"collector_extra": "batch_size = 0"}, {"collector_extra": "batch_size = 9999"}, {"collector_extra": 'batch_size = "ten"'},
                       {"collector_extra": 'log_level = "LOUD"'}, {"snort_extra": 'timezone = "Mars/Base"'}, {"collector_extra": "flush_interval_seconds = true"}):
            with self.assertRaises(ConfigError, msg=kwargs):
                self.cfg(**kwargs)

    def test_missing_file_and_bad_toml(self):
        with self.assertRaises(ConfigError):
            load(Path(self.dir.name) / "nope.toml")
        bad = Path(self.dir.name) / "bad.toml"
        bad.write_text("[server\nurl=")
        with self.assertRaises(ConfigError):
            load(bad)

    def test_shipped_example_configs_are_valid(self):
        root = Path(__file__).resolve().parents[1]
        for name in ("linux/collector.example.toml", "windows/collector.example.toml"):
            c = load(root / name)
            self.assertFalse(c.payloads_enabled, name)


if __name__ == "__main__":
    unittest.main()
