import base64
import hashlib
import unittest

from sentinel_collector import payload


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def ext(data, **kw):
    return payload.extract(b64(data) if isinstance(data, bytes) else data, **{"enabled": True, "min_bytes": 16, "max_b64_chars": 10_000, **kw})


class HashTests(unittest.TestCase):
    def test_sha256_and_size_match_the_decoded_bytes(self):
        data = bytes(range(256)) * 4
        r = ext(data)
        self.assertEqual(r["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(r["size"], len(data))

    def test_known_vector(self):
        self.assertEqual(ext(b"abc" * 10)["sha256"], hashlib.sha256(b"abc" * 10).hexdigest())
        self.assertEqual(payload.extract(b64(b"abc"), True, 1, 100)["sha256"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_result_contains_metadata_only(self):
        self.assertEqual(set(ext(b"x" * 100)), {"sha256", "size", "mime_type"})


class LimitTests(unittest.TestCase):
    def test_disabled_missing_and_wrong_types_give_none(self):
        self.assertIsNone(ext(b"x" * 100, enabled=False))
        for bad in (None, "", 123, ["QUJD"], {"a": 1}, b"raw bytes"):
            self.assertIsNone(payload.extract(bad, True, 1, 1000), bad)

    def test_invalid_base64_is_ignored_not_fatal(self):
        for bad in ("!!!not base64!!!", "QU JD", "A" * 5, "QUJD====x"):
            self.assertIsNone(payload.extract(bad, True, 1, 1000), bad)

    def test_too_small_and_too_large(self):
        self.assertIsNone(ext(b"tiny"))
        self.assertIsNone(ext(b"x" * 5000, max_b64_chars=100))


class MimeTests(unittest.TestCase):
    def test_magic_numbers(self):
        for head, mime in [(b"MZ\x90\x00", "application/vnd.microsoft.portable-executable"), (b"\x7fELF\x02", "application/x-elf"),
                           (b"%PDF-1.7", "application/pdf"), (b"PK\x03\x04", "application/zip"), (b"\x1f\x8b\x08", "application/gzip"),
                           (b"\x89PNG\r\n\x1a\n", "image/png"), (b"#!/bin/sh\n", "text/x-script")]:
            self.assertEqual(ext(head + b"\x00" * 40)["mime_type"], mime, head)

    def test_text_and_binary_fallbacks(self):
        self.assertEqual(ext(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")["mime_type"], "text/plain")
        self.assertEqual(ext(bytes([0, 1, 2, 3, 200, 201]) * 10)["mime_type"], "application/octet-stream")

    def test_payload_is_never_executed_or_written(self):
        import os
        import tempfile

        before = set(os.listdir(tempfile.gettempdir()))
        ext(b"MZ" + b"#!/bin/sh\nrm -rf /\n" * 10)
        self.assertEqual(set(os.listdir(tempfile.gettempdir())), before)


if __name__ == "__main__":
    unittest.main()
