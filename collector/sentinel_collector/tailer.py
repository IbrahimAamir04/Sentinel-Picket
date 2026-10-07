"""
Follows the Snort alert file without holding it open.

Each poll opens the file, reads what is new, and closes it. That matters on Windows, where an open handle can stop
Snort from rotating the file, and it makes rotation detection simple. Reading is separate from committing: the
position only advances after the batch has been delivered, so a failed send is simply read again.
"""
from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass

from .state import Position

log = logging.getLogger("sentinel.collector.tail")
READ_CHUNK = 4 * 1024 * 1024
MAX_LINES_PER_POLL = 5000


@dataclass
class Batch:
    lines: list[str]
    position: Position  # where to resume once these lines are delivered
    skipped_oversize: int = 0


HEAD_BYTES = 128


def file_id(st: os.stat_result) -> str:
    return f"{st.st_dev}:{st.st_ino}"


def make_head(head_bytes: bytes, offset: int) -> str:
    n = min(len(head_bytes), offset)
    return f"{n}:{hashlib.sha256(head_bytes[:n]).hexdigest()[:16]}" if n else ""


def head_matches(head: str, head_bytes: bytes) -> bool:
    try:
        n_text, _, digest = head.partition(":")
        n = int(n_text)
    except ValueError:
        return True  # unreadable fingerprint: do not discard a good position over it
    return len(head_bytes) >= n and hashlib.sha256(head_bytes[:n]).hexdigest()[:16] == digest


class Tailer:
    def __init__(self, path: str, start_at: str, max_line_bytes: int, position: Position | None = None):
        self.path, self.start_at, self.max_line_bytes = path, start_at, max_line_bytes
        self.position = position
        self._warned_missing = False

    def commit(self, position: Position) -> None:
        self.position = position

    def peek(self) -> Batch | None:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            if not self._warned_missing:
                log.warning("Alert file %s does not exist yet; waiting for Snort to create it.", self.path)
                self._warned_missing = True
            return None
        self._warned_missing = False
        fid = file_id(st)

        with open(self.path, "rb") as f:
            head_bytes = f.read(HEAD_BYTES)
            pos = self.position
            if pos is None:
                offset = 0 if self.start_at == "beginning" else st.st_size
                pos = Position(fid, offset, make_head(head_bytes, offset))
            elif pos.file_id != fid:
                log.info("Alert file was rotated or replaced; reading the new file from the start.")
                pos = Position(fid, 0)
            elif st.st_size < pos.offset:
                log.info("Alert file was truncated; reading from the start.")
                pos = Position(fid, 0)
            elif pos.head and not head_matches(pos.head, head_bytes):
                log.info("Alert file was replaced (same file id, different content); reading from the start.")
                pos = Position(fid, 0)

            if st.st_size <= pos.offset:
                return Batch([], pos)
            f.seek(pos.offset)
            data = f.read(min(READ_CHUNK, st.st_size - pos.offset))

        last_nl = data.rfind(b"\n")
        if last_nl == -1:
            if len(data) >= self.max_line_bytes:
                # A runaway line with no end in sight. Drop what we have; its tail will fail JSON parsing and be skipped.
                log.warning("Discarding %d bytes of an over-long line.", len(data))
                new_offset = pos.offset + len(data)
                return Batch([], Position(fid, new_offset, make_head(head_bytes, new_offset)), skipped_oversize=1)
            return Batch([], pos)  # a line Snort is still writing; wait for its newline

        lines: list[str] = []
        skipped = consumed = 0
        for part in data[:last_nl].split(b"\n")[:MAX_LINES_PER_POLL]:
            consumed += len(part) + 1
            if len(part) > self.max_line_bytes:
                skipped += 1
                continue
            text = part.decode("utf-8", errors="replace").strip()
            if text:
                lines.append(text)
        new_offset = pos.offset + consumed
        return Batch(lines, Position(fid, new_offset, make_head(head_bytes, new_offset)), skipped)
