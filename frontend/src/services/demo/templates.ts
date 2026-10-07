import type { Severity } from "../../types";

/**
 * Synthetic rule catalogue. Messages are written in the style of Snort rule msg strings but are
 * invented for the demo. Classification names follow Snort's classification.config naming.
 * Priority follows the Snort convention (1 = highest). The severity mapping here is a demo
 * placeholder; the real mapping is defined in the ingestion layer (Phase 3).
 */
export interface RuleTemplate {
  sid: number;
  msg: string;
  classification: string;
  priority: number;
  severity: Severity;
  protocol: "TCP" | "UDP" | "ICMP";
  ports: number[];
  weight: number;
  payload: boolean;
}

export const RULES: RuleTemplate[] = [
  { sid: 1000101, msg: "DEMO MALWARE-CNC beacon over HTTP", classification: "trojan-activity", priority: 1, severity: "CRITICAL", protocol: "TCP", ports: [80, 8080], weight: 5, payload: true },
  { sid: 1000102, msg: "DEMO SERVER-WEBAPP command injection attempt", classification: "web-application-attack", priority: 1, severity: "CRITICAL", protocol: "TCP", ports: [80, 443, 8443], weight: 6, payload: true },
  { sid: 1000103, msg: "DEMO FILE-EXECUTABLE Windows PE download", classification: "trojan-activity", priority: 1, severity: "HIGH", protocol: "TCP", ports: [80, 443], weight: 7, payload: true },
  { sid: 1000104, msg: "DEMO SERVER-SMB suspicious named pipe access", classification: "attempted-admin", priority: 1, severity: "HIGH", protocol: "TCP", ports: [445, 139], weight: 6, payload: false },
  { sid: 1000105, msg: "DEMO PROTOCOL-RDP repeated login failures", classification: "attempted-user", priority: 2, severity: "HIGH", protocol: "TCP", ports: [3389], weight: 8, payload: false },
  { sid: 1000106, msg: "DEMO SERVER-WEBAPP SQL injection attempt", classification: "web-application-attack", priority: 2, severity: "HIGH", protocol: "TCP", ports: [80, 443], weight: 9, payload: true },
  { sid: 1000107, msg: "DEMO FILE-OFFICE macro document download", classification: "suspicious-filename-detected", priority: 2, severity: "MEDIUM", protocol: "TCP", ports: [80, 443], weight: 6, payload: true },
  { sid: 1000108, msg: "DEMO PROTOCOL-DNS tunneling pattern", classification: "bad-unknown", priority: 2, severity: "MEDIUM", protocol: "UDP", ports: [53], weight: 7, payload: false },
  { sid: 1000109, msg: "DEMO PROTOCOL-SSH brute force attempt", classification: "attempted-user", priority: 2, severity: "MEDIUM", protocol: "TCP", ports: [22], weight: 14, payload: false },
  { sid: 1000110, msg: "DEMO POLICY-OTHER outbound TLS to rare destination", classification: "policy-violation", priority: 3, severity: "MEDIUM", protocol: "TCP", ports: [443, 8443], weight: 8, payload: false },
  { sid: 1000111, msg: "DEMO PROTOCOL-ICMP large echo request", classification: "misc-activity", priority: 3, severity: "LOW", protocol: "ICMP", ports: [], weight: 9, payload: false },
  { sid: 1000112, msg: "DEMO SCAN TCP SYN sweep", classification: "attempted-recon", priority: 3, severity: "LOW", protocol: "TCP", ports: [22, 23, 80, 443, 445, 3389], weight: 16, payload: false },
  { sid: 1000113, msg: "DEMO PROTOCOL-NTP monlist query", classification: "attempted-dos", priority: 3, severity: "LOW", protocol: "UDP", ports: [123], weight: 5, payload: false },
  { sid: 1000114, msg: "DEMO INDICATOR-SCAN UPnP discovery probe", classification: "network-scan", priority: 3, severity: "LOW", protocol: "UDP", ports: [1900], weight: 6, payload: false },
];

export const SENSOR_DEFS = [
  { name: "linux-edge-01", hostname: "edge01.demo.invalid", os: "LINUX" as const, ip: "10.20.0.11", snort_version: "3.3.2.0", weight: 38 },
  { name: "linux-dmz-02", hostname: "dmz02.demo.invalid", os: "LINUX" as const, ip: "10.20.1.12", snort_version: "3.3.2.0", weight: 27 },
  { name: "win-srv-01", hostname: "srv01.demo.invalid", os: "WINDOWS" as const, ip: "10.30.0.21", snort_version: "3.3.1.0", weight: 22 },
  { name: "win-ws-02", hostname: "ws02.demo.invalid", os: "WINDOWS" as const, ip: "10.30.4.32", snort_version: "3.3.1.0", weight: 13 },
];

export const FILE_TYPES = [
  { mime: "application/vnd.microsoft.portable-executable", ext: "exe", names: ["update_helper", "setup_tool", "svc_host32", "invoice_viewer"], min: 90_000, max: 2_400_000 },
  { mime: "application/x-dosexec", ext: "dll", names: ["netutils", "libcurl_x", "shellext"], min: 30_000, max: 900_000 },
  { mime: "application/pdf", ext: "pdf", names: ["invoice_2291", "statement", "shipping_notice"], min: 40_000, max: 1_200_000 },
  { mime: "application/vnd.ms-office", ext: "doc", names: ["report_q3", "order_form", "resume"], min: 20_000, max: 600_000 },
  { mime: "application/zip", ext: "zip", names: ["documents", "photos", "package"], min: 15_000, max: 3_000_000 },
  { mime: "application/x-sh", ext: "sh", names: ["install", "fetch", "run"], min: 300, max: 12_000 },
  { mime: "text/html", ext: "html", names: ["login", "portal", "redirect"], min: 800, max: 60_000 },
  { mime: "application/octet-stream", ext: "bin", names: ["blob", "data", "chunk"], min: 200, max: 400_000 },
];
