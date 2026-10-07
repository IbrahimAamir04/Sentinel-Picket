"""
Payload metadata from Snort's `b64_data` field.

IMPORTANT: b64_data is the data segment of ONE packet, not a reassembled file. Hashing it identifies that packet's
bytes. A file split across many packets yields a different hash per packet, so a VirusTotal lookup of these hashes
will usually come back unknown. Reassembled-file hashes need Snort's file inspection (not implemented here).

The decoded bytes are hashed in memory and discarded. They are never written to disk, never sent to the server,
and never interpreted or executed.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import logging

log = logging.getLogger("sentinel.collector.payload")

# (leading bytes, MIME type). Indicative only: a guess from the first few bytes.
_MAGIC = [
    (b"MZ", "application/vnd.microsoft.portable-executable"),
    (b"\x7fELF", "application/x-elf"),
    (b"%PDF-", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),
    (b"\x1f\x8b", "application/gzip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage"),
    (b"Rar!\x1a\x07", "application/vnd.rar"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF8", "image/gif"),
    (b"#!", "text/x-script"),
]


def sniff_mime(data: bytes) -> str:
    head = data[:16]
    for magic, mime in _MAGIC:
        if head.startswith(magic):
            return mime
    sample = data[:512]
    if sample and all(b in (9, 10, 13) or 32 <= b < 127 for b in sample):
        return "text/plain"
    return "application/octet-stream"


def extract(b64: object, enabled: bool, min_bytes: int, max_b64_chars: int) -> dict | None:
    """Returns {sha256, size, mime_type} or None. Never raises on bad input: most alerts simply carry no usable payload."""
    if not enabled or not isinstance(b64, str) or not b64:
        return None
    if len(b64) > max_b64_chars:
        log.debug("Payload skipped: %d base64 characters exceeds the limit", len(b64))
        return None
    try:
        data = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        log.debug("Payload skipped: not valid base64")
        return None
    if len(data) < min_bytes:
        return None
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "mime_type": sniff_mime(data)}
