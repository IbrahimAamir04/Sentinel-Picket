"""
The delivery loop.

Guarantee: a line of the Snort file is only marked as done after the server has accepted it (or has definitively
refused it, which retrying cannot fix). A crash, restart, network outage or server error therefore never loses an
alert, and the server drops the duplicates that at-least-once delivery can produce.
"""
from __future__ import annotations

import logging
import random
import threading
import time
from collections import Counter
from typing import Callable

from . import __version__, snort, sysinfo
from .client import Client, TransientError, classify
from .config import Config
from .state import StateStore
from .tailer import Tailer

log = logging.getLogger("sentinel.collector")
MAX_BACKOFF = 60.0
MAX_AUTH_BACKOFF = 300.0


class Shutdown(Exception):
    pass


def chunks(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]


class Runner:
    def __init__(self, cfg: Config, client: Client, tailer: Tailer, state: StateStore | None,
                 stop: threading.Event | None = None, sleep: Callable[[float], None] | None = None):
        self.cfg, self.client, self.tailer, self.state = cfg, client, tailer, state
        self.stop = stop or threading.Event()
        self._sleep = sleep or (lambda s: self.stop.wait(s))
        self._last_heartbeat = float("-inf")
        self.stats = Counter()

    # -- parsing ------------------------------------------------------------------------------------------
    def parse(self, lines: list[str]) -> list[dict]:
        events, skipped = [], Counter()
        for line in lines:
            try:
                events.append(snort.normalize(
                    snort.parse_line(line), tz_name=self.cfg.timezone, payloads_enabled=self.cfg.payloads_enabled,
                    payload_min_bytes=self.cfg.payload_min_bytes, payload_max_b64_chars=self.cfg.payload_max_b64_chars))
            except snort.SkipEvent as e:
                skipped[str(e)] += 1
        for reason, n in skipped.items():
            self.stats["skipped"] += n
            log.warning("Skipped %d line(s): %s", n, reason)
        return events

    # -- delivery -----------------------------------------------------------------------------------------
    def _wait(self, seconds: float) -> None:
        self._sleep(seconds)
        if self.stop.is_set():
            raise Shutdown()

    def deliver(self, events: list[dict]) -> None:
        attempt = 0
        while True:
            if self.stop.is_set():
                raise Shutdown()
            try:
                resp = self.client.send_events(events)
            except TransientError as e:
                attempt += 1
                delay = min(MAX_BACKOFF, 2 ** min(attempt, 6)) + random.uniform(0, 1)
                log.warning("Cannot reach the server (%s). Retrying in %.0fs; %d event(s) are safe on disk.", e, delay, len(events))
                self._wait(delay)
                continue

            kind = classify(resp.status)
            if kind == "ok":
                body = resp.body
                self.stats["accepted"] += int(body.get("accepted", 0))
                self.stats["duplicates"] += int(body.get("duplicates", 0))
                self.stats["rejected"] += int(body.get("rejected", 0))
                log.info("Delivered %d event(s): accepted=%s duplicates=%s rejected=%s",
                         len(events), body.get("accepted"), body.get("duplicates"), body.get("rejected"))
                for err in (body.get("errors") or [])[:3]:
                    log.warning("Server rejected event %s: %s", err.get("index"), err.get("errors"))
                return
            if kind == "split":
                if len(events) > 1:
                    mid = len(events) // 2
                    log.warning("Server says the request is too large; sending in two halves.")
                    self.deliver(events[:mid])
                    self.deliver(events[mid:])
                    return
                log.error("A single event is too large for the server; dropping it.")
                self.stats["dropped"] += 1
                return
            if kind == "drop":
                log.error("Server refused %d event(s) with HTTP %s and retrying cannot help; dropping them. Detail: %s",
                          len(events), resp.status, resp.body.get("detail", ""))
                self.stats["dropped"] += len(events)
                return

            attempt += 1
            if kind == "auth":
                delay = min(MAX_AUTH_BACKOFF, 15 * attempt)
                log.error("HTTP %s: the server rejected this sensor's API key (wrong, rotated, or sensor disabled). "
                          "Events are kept and will be sent once fixed. Retrying in %.0fs.", resp.status, delay)
            else:
                delay = resp.retry_after if resp.retry_after else min(MAX_BACKOFF, 2 ** min(attempt, 6))
                log.warning("Server answered HTTP %s (%s). Retrying in %.0fs.", resp.status, resp.body.get("detail", ""), delay)
            self._wait(delay + random.uniform(0, 1))

    # -- one pass -----------------------------------------------------------------------------------------
    def step(self) -> int:
        batch = self.tailer.peek()
        if batch is None:
            return 0
        if batch.skipped_oversize:
            self.stats["skipped"] += batch.skipped_oversize
            log.warning("Skipped %d over-long line(s).", batch.skipped_oversize)
        events = self.parse(batch.lines)
        for group in chunks(events, self.cfg.batch_size):
            self.deliver(group)
        if batch.position != self.tailer.position:
            self.tailer.commit(batch.position)
            if self.state:
                self.state.save(batch.position)
        return len(batch.lines)

    def heartbeat(self) -> None:
        info = {"collector_version": __version__}
        if (name := sysinfo.os_name()):
            info["os"] = name
        import socket

        info["hostname"] = socket.gethostname()
        if (ip := self.cfg.sensor_ip or sysinfo.primary_ip()):
            info["ip"] = ip
        if self.cfg.snort_version:
            info["snort_version"] = self.cfg.snort_version
        try:
            resp = self.client.heartbeat(info)
            if classify(resp.status) != "ok":
                log.warning("Heartbeat refused: HTTP %s %s", resp.status, resp.body.get("detail", ""))
        except TransientError as e:
            log.warning("Heartbeat failed (%s).", e)

    def run_forever(self) -> None:
        log.info("Collector %s started. Watching %s", __version__, self.cfg.alert_file)
        try:
            while not self.stop.is_set():
                now = time.monotonic()
                if now - self._last_heartbeat >= self.cfg.heartbeat_interval_seconds:
                    self.heartbeat()
                    self._last_heartbeat = now
                if self.step() == 0:
                    self._sleep(self.cfg.flush_interval_seconds)
        except Shutdown:
            log.info("Stopping. Undelivered events stay in the Snort file and are sent on the next start.")
