"""HTTP client for the Sentinel ingestion API. Standard library only."""
from __future__ import annotations

import json
import logging
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass

from . import __version__
from .config import Config

log = logging.getLogger("sentinel.collector.client")
MAX_RESPONSE_BYTES = 64 * 1024


class TransientError(Exception):
    """Network-level failure (refused, DNS, timeout, TLS). Always worth retrying."""


@dataclass
class Response:
    status: int
    body: dict
    retry_after: float | None = None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: urllib would re-send the Authorization header to wherever the redirect points."""

    def redirect_request(self, *args, **kwargs):
        return None


def classify(status: int) -> str:
    if 200 <= status < 300:
        return "ok"
    if status in (408, 425, 429) or status >= 500:
        return "retry"
    if status in (401, 403):
        return "auth"
    if status == 409:
        return "retry"  # the server is refusing ingestion right now (e.g. demo mode); keep the data and try again later
    if status == 413:
        return "split"
    return "drop"  # 3xx, 400, 404, 415...: retrying the identical request cannot succeed


class Client:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        ctx = ssl.create_default_context(cafile=cfg.ca_file or None)
        self._opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))

    def _post(self, path: str, payload: dict) -> Response:
        req = urllib.request.Request(
            self.cfg.url + path, data=json.dumps(payload, separators=(",", ":")).encode(), method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json",
                     "Authorization": f"Bearer {self.cfg.api_key}", "User-Agent": f"sentinel-collector/{__version__}"},
        )
        try:
            with self._opener.open(req, timeout=self.cfg.timeout_seconds) as r:
                return Response(r.status, self._body(r))
        except urllib.error.HTTPError as e:
            retry_after = None
            try:
                retry_after = float(e.headers.get("Retry-After", ""))
            except ValueError:
                pass
            return Response(e.code, self._body(e), retry_after)
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, ssl.SSLError, OSError) as e:
            # Never include the request (it carries the key) in the message.
            raise TransientError(getattr(e, "reason", None) or type(e).__name__)

    @staticmethod
    def _body(r) -> dict:
        try:
            data = json.loads(r.read(MAX_RESPONSE_BYTES) or b"{}")
            return data if isinstance(data, dict) else {}
        except (ValueError, OSError):
            return {}

    def send_events(self, events: list[dict]) -> Response:
        return self._post("/api/ingest/events", {"schema": 1, "events": events})

    def heartbeat(self, info: dict) -> Response:
        return self._post("/api/ingest/heartbeat", info)
