"""
SYNTHETIC catalogue used only by the demo seeder. Rule messages are invented (prefixed DEMO), classification
names follow Snort's classification.config naming, and the severity mapping is a placeholder: the real mapping
is decided in the ingestion layer (Phase 3).
"""
RULES = [
    # sid, msg, classification, priority, severity, protocol, ports, weight, has_payload
    (1000101, "DEMO MALWARE-CNC beacon over HTTP", "trojan-activity", 1, "CRITICAL", "TCP", [80, 8080], 5, True),
    (1000102, "DEMO SERVER-WEBAPP command injection attempt", "web-application-attack", 1, "CRITICAL", "TCP", [80, 443, 8443], 6, True),
    (1000103, "DEMO FILE-EXECUTABLE Windows PE download", "trojan-activity", 1, "HIGH", "TCP", [80, 443], 7, True),
    (1000104, "DEMO SERVER-SMB suspicious named pipe access", "attempted-admin", 1, "HIGH", "TCP", [445, 139], 6, False),
    (1000105, "DEMO PROTOCOL-RDP repeated login failures", "attempted-user", 2, "HIGH", "TCP", [3389], 8, False),
    (1000106, "DEMO SERVER-WEBAPP SQL injection attempt", "web-application-attack", 2, "HIGH", "TCP", [80, 443], 9, True),
    (1000107, "DEMO FILE-OFFICE macro document download", "suspicious-filename-detected", 2, "MEDIUM", "TCP", [80, 443], 6, True),
    (1000108, "DEMO PROTOCOL-DNS tunneling pattern", "bad-unknown", 2, "MEDIUM", "UDP", [53], 7, False),
    (1000109, "DEMO PROTOCOL-SSH brute force attempt", "attempted-user", 2, "MEDIUM", "TCP", [22], 14, False),
    (1000110, "DEMO POLICY-OTHER outbound TLS to rare destination", "policy-violation", 3, "MEDIUM", "TCP", [443, 8443], 8, False),
    (1000111, "DEMO PROTOCOL-ICMP large echo request", "misc-activity", 3, "LOW", "ICMP", [], 9, False),
    (1000112, "DEMO SCAN TCP SYN sweep", "attempted-recon", 3, "LOW", "TCP", [22, 23, 80, 443, 445, 3389], 16, False),
    (1000113, "DEMO PROTOCOL-NTP monlist query", "attempted-dos", 3, "LOW", "UDP", [123], 5, False),
    (1000114, "DEMO INDICATOR-SCAN UPnP discovery probe", "network-scan", 3, "LOW", "UDP", [1900], 6, False),
]
OUTBOUND_SIDS = {1000101, 1000108, 1000110}

SENSORS = [
    # name, hostname, os, ip, snort_version, weight, heartbeat
    ("linux-edge-01", "edge01.demo.invalid", "LINUX", "10.20.0.11", "3.3.2.0", 38, "live"),
    ("linux-dmz-02", "dmz02.demo.invalid", "LINUX", "10.20.1.12", "3.3.2.0", 27, "live"),
    ("win-srv-01", "srv01.demo.invalid", "WINDOWS", "10.30.0.21", "3.3.1.0", 22, 5 * 60),       # late -> WARNING
    ("win-ws-02", "ws02.demo.invalid", "WINDOWS", "10.30.4.32", "3.3.1.0", 13, 3 * 60 * 60),     # silent -> OFFLINE
]

FILE_TYPES = [
    ("application/vnd.microsoft.portable-executable", "exe", ["update_helper", "setup_tool", "svc_host32", "invoice_viewer"], 90_000, 2_400_000),
    ("application/x-dosexec", "dll", ["netutils", "libcurl_x", "shellext"], 30_000, 900_000),
    ("application/pdf", "pdf", ["invoice_2291", "statement", "shipping_notice"], 40_000, 1_200_000),
    ("application/vnd.ms-office", "doc", ["report_q3", "order_form", "resume"], 20_000, 600_000),
    ("application/zip", "zip", ["documents", "photos", "package"], 15_000, 3_000_000),
    ("application/x-sh", "sh", ["install", "fetch", "run"], 300, 12_000),
    ("text/html", "html", ["login", "portal", "redirect"], 800, 60_000),
    ("application/octet-stream", "bin", ["blob", "data", "chunk"], 200, 400_000),
]
EXTERNAL_PREFIXES = ["203.0.113", "198.51.100", "192.0.2"]  # RFC 5737 documentation ranges
