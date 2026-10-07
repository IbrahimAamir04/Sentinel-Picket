"""
Writes SYNTHETIC Snort 3 alert_json lines for testing the pipeline without Snort.

These are hand-built to match the documented alert_json format. They are NOT captured traffic. Every message starts
with "SYNTHETIC TEST", so they are easy to find and delete. Send them only to a test server or scratch database.
"""
from __future__ import annotations

import base64
import json
import random
import sys
from datetime import datetime, timedelta

PAYLOAD_PE = base64.b64encode(b"MZ\x90\x00" + b"synthetic test bytes, not a real executable " * 4).decode()
PAYLOAD_TEXT = base64.b64encode(b"GET /synthetic-test HTTP/1.1\r\nHost: example.invalid\r\n\r\n").decode()

RULES = [  # gid:sid:rev, msg, class, priority, proto, dst port
    ("1:1900001:1", "SYNTHETIC TEST trojan beacon", "trojan-activity", 1, "TCP", 80),
    ("1:1900002:1", "SYNTHETIC TEST web attack", "web-application-attack", 1, "TCP", 443),
    ("1:1900003:2", "SYNTHETIC TEST suspicious login", "suspicious-login", 2, "TCP", 22),
    ("1:1900004:1", "SYNTHETIC TEST DNS oddity", "bad-unknown", 2, "UDP", 53),
    ("1:1900005:1", "SYNTHETIC TEST ICMP event", "icmp-event", 3, "ICMP", 0),
]


def generate(count: int, with_seconds: bool = True, seed: int = 1):
    rng = random.Random(seed)
    now = datetime.now().astimezone()
    for i in range(count):
        rule, msg, cls, prio, proto, dport = RULES[i % len(RULES)]
        when = now - timedelta(seconds=(count - i) * 7)
        ev = {
            "timestamp": when.strftime("%m/%d-%H:%M:%S.%f"),
            "pkt_num": 100 + i, "proto": proto, "pkt_gen": "raw", "pkt_len": 80 + i, "dir": "C2S",
            "src_addr": f"198.51.100.{rng.randint(2, 250)}", "src_port": 0 if proto == "ICMP" else rng.randint(1025, 65000),
            "dst_addr": f"192.0.2.{rng.randint(2, 250)}", "dst_port": dport,
            "rule": rule, "msg": msg, "class": cls, "priority": prio, "action": "allow",
        }
        if with_seconds:
            ev["seconds"] = int(when.timestamp())
        if i % 5 == 0 and proto == "TCP":
            ev["b64_data"] = PAYLOAD_PE if i % 10 == 0 else PAYLOAD_TEXT
        yield json.dumps(ev, separators=(",", ":"))


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    for line in generate(n, with_seconds="--no-seconds" not in sys.argv):
        print(line)
