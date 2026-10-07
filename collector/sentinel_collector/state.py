"""Remembers how far into the Snort file we have safely delivered, so a restart neither loses nor repeats work."""
from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass
from pathlib import Path

log = logging.getLogger("sentinel.collector.state")


@dataclass(frozen=True)
class Position:
    file_id: str  # device:inode (or the Windows file index), to notice rotation
    offset: int
    head: str = ""  # "length:digest" of the file's first bytes: catches a file deleted and recreated under the same inode


class StateStore:
    def __init__(self, path: str | Path, alert_file: str):
        self.path = Path(path)
        self.alert_file = alert_file

    def load(self) -> Position | None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("state is not an object")
            if data.get("alert_file") != self.alert_file:
                log.info("State belongs to a different alert file; ignoring it.")
                return None
            return Position(str(data["file_id"]), int(data["offset"]), str(data.get("head", "")))
        except FileNotFoundError:
            return None
        except (ValueError, KeyError, TypeError, OSError) as e:
            # Safe: the server drops duplicates, so re-reading is harmless.
            log.warning("State file unreadable (%s); starting as a first run.", type(e).__name__)
            return None

    def save(self, pos: Position) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({**asdict(pos), "alert_file": self.alert_file}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)  # atomic: a crash leaves the old state or the new one, never half of one
