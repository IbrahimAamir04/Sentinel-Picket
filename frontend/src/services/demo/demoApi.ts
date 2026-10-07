import type {
  Alert, DashboardStats, ListQuery, Payload, PayloadStatus, PayloadSummary, PayloadTrendPoint,
  Severity, TimelinePoint, TimelineRange, VtActionResult,
} from "../../types";
import { deriveSensorStatus } from "../../utils/sensorStatus";
import { ApiError, type SentinelApi } from "../api";
import { searchSortPaginate } from "../query";
import { createRng } from "./prng";
import { buildDataset, type DemoDataset } from "./seed";

/**
 * Demo implementation of SentinelApi. Everything is computed from the in-memory synthetic dataset,
 * exactly as the backend will compute it from PostgreSQL. No network request is ever made, and
 * the two VirusTotal actions are simulated and say so.
 *
 * Append ?demo_fail=1 to the URL to force every request to fail (to exercise error states).
 */

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const SEV_RANK: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

// Built on first use so importing this module has no side effects (lets the bundler drop it in API mode).
let cache: DemoDataset | undefined;
const data = /* @__PURE__ */ new Proxy({} as DemoDataset, {
  get: (_t, key) => (cache ??= buildDataset())[key as keyof DemoDataset],
});

const delay = () => new Promise((r) => setTimeout(r, 120 + Math.random() * 220));
async function guard() {
  await delay();
  if (typeof window !== "undefined" && new URLSearchParams(window.location.search).get("demo_fail") === "1") {
    throw new ApiError("Demo failure mode is on (demo_fail=1). Remove it from the URL to restore data.", 503);
  }
}

const liveSensors = () => {
  const now = Date.now();
  return data.sensors.map((s, i) => {
    const seen = data.sensorSeen[i].lastSeenAt;
    const last_seen = seen === "live" ? new Date(now - 2_000 - ((now / 1000) % 17) * 1000).toISOString() : s.last_seen;
    return { ...s, last_seen, status: deriveSensorStatus(last_seen, now) };
  });
};

const dayStart = (iso: string, endOfDay = false) => {
  const d = new Date(`${iso}T00:00:00`);
  return endOfDay ? d.getTime() + DAY - 1 : d.getTime();
};

function filterAlerts(q: ListQuery): Alert[] {
  return data.alerts.filter((a) => {
    if (q.severity && a.severity !== q.severity) return false;
    if (q.sensor && String(a.sensor_id) !== String(q.sensor)) return false;
    if (q.protocol && a.protocol !== q.protocol) return false;
    if (q.rule && String(a.signature_id) !== String(q.rule)) return false;
    if (q.has_payload === "true" && !a.payload_available) return false;
    const t = new Date(a.timestamp).getTime();
    if (q.date_from && t < dayStart(String(q.date_from))) return false;
    if (q.date_to && t > dayStart(String(q.date_to), true)) return false;
    return true;
  });
}

function simulateLookup(p: Payload): VtActionResult {
  const rng = createRng(parseInt(p.sha256.slice(0, 8), 16));
  const now = new Date().toISOString();
  // Hashes starting 0-7 behave as "known to VirusTotal"; the rest as "never seen". Deterministic per hash.
  const known = p.status !== "UNKNOWN" && p.status !== "ERROR" ? true : parseInt(p.sha256[0], 16) < 8;
  if (!known) {
    p.status = "UNKNOWN";
    p.vt_last_checked = now;
    return { payload: { ...p }, simulated: true, message: "Simulated lookup: this hash is not known to VirusTotal. The file was not uploaded." };
  }
  if (p.vt_total == null) {
    const outcome: PayloadStatus = rng.weighted([{ item: "CLEAN", weight: 4 }, { item: "SUSPICIOUS", weight: 2 }, { item: "MALICIOUS", weight: 3 }]);
    const total = rng.int(68, 74);
    const mal = outcome === "MALICIOUS" ? rng.int(14, 58) : outcome === "SUSPICIOUS" ? rng.int(0, 3) : 0;
    const sus = outcome === "MALICIOUS" ? rng.int(0, 6) : outcome === "SUSPICIOUS" ? rng.int(3, 9) : 0;
    Object.assign(p, { status: outcome, vt_malicious: mal, vt_suspicious: sus, vt_undetected: total - mal - sus, vt_total: total });
  }
  p.vt_last_checked = now;
  return { payload: { ...p }, simulated: true, message: "Simulated lookup: result refreshed from demo data. No request was sent to VirusTotal." };
}

export const demoApi: SentinelApi = {
  async meta() {
    await guard();
    return { mode: "demo", generated_at: new Date().toISOString(), features: { virustotal: true, realtime: false } };
  },

  async dashboardStats(): Promise<DashboardStats> {
    await guard();
    const by_severity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 } as Record<Severity, number>;
    const cls = new Map<string, number>();
    for (const a of data.alerts) {
      by_severity[a.severity]++;
      cls.set(a.classification, (cls.get(a.classification) ?? 0) + 1);
    }
    const malicious = data.payloads.filter((p) => p.status === "MALICIOUS").length;
    const checked = data.payloads.filter((p) => p.vt_total != null).length;
    return {
      total_alerts: data.alerts.length, by_severity,
      total_payloads: data.payloads.length, malicious_payloads: malicious, checked_payloads: checked,
      detection_rate: checked ? malicious / checked : 0,
      classifications: [...cls].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count),
    };
  },

  async dashboardTimeline(range: TimelineRange): Promise<TimelinePoint[]> {
    await guard();
    const step = range === "24h" ? HOUR : DAY;
    const n = range === "24h" ? 24 : 7;
    const now = Date.now();
    const end = Math.ceil(now / step) * step;
    const points: TimelinePoint[] = Array.from({ length: n }, (_, i) => ({
      bucket: new Date(end - (n - i) * step).toISOString(), CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0,
    }));
    const first = end - n * step;
    for (const a of data.alerts) {
      const t = new Date(a.timestamp).getTime();
      if (t < first || t > end) continue;
      points[Math.min(n - 1, Math.floor((t - first) / step))][a.severity]++;
    }
    return points;
  },

  async dashboardProtocols() {
    await guard();
    const m = new Map<string, number>();
    for (const a of data.alerts) m.set(a.protocol, (m.get(a.protocol) ?? 0) + 1);
    return [...m].map(([protocol, count]) => ({ protocol, count })).sort((a, b) => b.count - a.count);
  },

  async dashboardRules(limit = 8) {
    await guard();
    const m = new Map<number, { signature: string; classification: string; count: number }>();
    for (const a of data.alerts) {
      const cur = m.get(a.signature_id) ?? { signature: a.signature, classification: a.classification, count: 0 };
      cur.count++;
      m.set(a.signature_id, cur);
    }
    return [...m].map(([signature_id, v]) => ({ signature_id, ...v })).sort((a, b) => b.count - a.count).slice(0, limit);
  },

  async listAlerts(q) {
    await guard();
    return searchSortPaginate(
      filterAlerts(q), q,
      (a) => [a.signature, a.signature_id, a.classification, a.source_ip, a.destination_ip, a.sensor_name, a.protocol, a.payload_hash ?? ""].join(" "),
      {
        timestamp: (a) => a.timestamp, severity: (a) => SEV_RANK[a.severity], signature: (a) => a.signature,
        classification: (a) => a.classification, source_ip: (a) => a.source_ip, destination_ip: (a) => a.destination_ip,
        protocol: (a) => a.protocol, sensor: (a) => a.sensor_name, payload: (a) => (a.payload_available ? 1 : 0),
      },
      "-timestamp",
    );
  },

  async getAlert(id) {
    await guard();
    const a = data.alerts.find((x) => x.id === id);
    if (!a) throw new ApiError(`Alert ${id} was not found.`, 404);
    return a;
  },

  async listSensors() {
    await guard();
    return liveSensors();
  },

  async filterOptions() {
    await guard();
    const rules = new Map<number, string>();
    for (const a of data.alerts) rules.set(a.signature_id, a.signature);
    return {
      sensors: data.sensors.map((s) => ({ id: s.id, name: s.name })),
      protocols: [...new Set(data.alerts.map((a) => a.protocol))].sort(),
      rules: [...rules].map(([signature_id, signature]) => ({ signature_id, signature })).sort((a, b) => a.signature.localeCompare(b.signature)),
    };
  },

  async listPayloads(q) {
    await guard();
    const rows = data.payloads.filter((p) => {
      if (q.status && p.status !== q.status) return false;
      if (q.sensor && String(p.sensor_id) !== String(q.sensor)) return false;
      return true;
    });
    return searchSortPaginate(
      rows, q,
      (p) => [p.sha256, p.filename ?? "", p.mime_type, p.snort_rule, p.sensor_name, p.signature_id].join(" "),
      {
        sha256: (p) => p.sha256, first_seen: (p) => p.first_seen, size: (p) => p.size, mime_type: (p) => p.mime_type,
        sensor: (p) => p.sensor_name, snort_rule: (p) => p.snort_rule, vt_detection: (p) => p.vt_malicious ?? -1, status: (p) => p.status,
      },
      "-first_seen",
    );
  },

  async getPayload(sha256) {
    await guard();
    const p = data.payloads.find((x) => x.sha256 === sha256.toLowerCase());
    if (!p) throw new ApiError("Payload not found.", 404);
    return { ...p };
  },

  async payloadSummary(): Promise<PayloadSummary> {
    await guard();
    const s: PayloadSummary = { total: data.payloads.length, MALICIOUS: 0, SUSPICIOUS: 0, CLEAN: 0, UNKNOWN: 0, ERROR: 0 };
    for (const p of data.payloads) s[p.status]++;
    return s;
  },

  async payloadTrend(): Promise<PayloadTrendPoint[]> {
    await guard();
    const days = 14;
    const end = new Date(); end.setHours(24, 0, 0, 0);
    const pts: PayloadTrendPoint[] = Array.from({ length: days }, (_, i) => ({
      day: new Date(end.getTime() - (days - i) * DAY).toISOString(), MALICIOUS: 0, SUSPICIOUS: 0, CLEAN: 0, UNKNOWN: 0,
    }));
    const start = end.getTime() - days * DAY;
    for (const p of data.payloads) {
      const t = new Date(p.first_seen).getTime();
      if (t < start) continue;
      const idx = Math.min(days - 1, Math.floor((t - start) / DAY));
      const key = p.status === "ERROR" ? "UNKNOWN" : p.status;
      pts[idx][key]++;
    }
    return pts;
  },

  async checkVirusTotal(sha256) {
    await guard();
    const p = data.payloads.find((x) => x.sha256 === sha256);
    if (!p) throw new ApiError("Payload not found.", 404);
    return simulateLookup(p);
  },

  async submitForAnalysis(sha256) {
    await guard();
    const p = data.payloads.find((x) => x.sha256 === sha256);
    if (!p) throw new ApiError("Payload not found.", 404);
    p.vt_submitted_at = new Date().toISOString();
    return {
      payload: { ...p }, simulated: true,
      message: "Simulated upload: no file left this browser. In live mode the file is sent to VirusTotal and the result appears after analysis completes.",
    };
  },
};

