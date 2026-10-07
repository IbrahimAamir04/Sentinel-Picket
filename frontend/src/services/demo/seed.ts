import type { Alert, Payload, PayloadStatus, Sensor } from "../../types";
import { deriveSensorStatus } from "../../utils/sensorStatus";
import { createRng } from "./prng";
import { FILE_TYPES, RULES, SENSOR_DEFS } from "./templates";

/**
 * SYNTHETIC DATA ONLY. Every record produced here is invented for the demo UI.
 * External addresses use RFC 5737 documentation ranges and hostnames use .invalid,
 * so nothing here can be mistaken for real telemetry or real indicators.
 */

const DAY = 86_400_000;
const EXTERNAL_PREFIXES = ["203.0.113", "198.51.100", "192.0.2"];
const OUTBOUND_SIDS = new Set([1000101, 1000108, 1000110]);
const ALERT_COUNT = 720;
const PAYLOAD_COUNT = 72;
const SPAN_DAYS = 14;

export interface DemoDataset {
  sensors: Sensor[];
  alerts: Alert[];
  payloads: Payload[];
  /** Offsets (seconds before load) used to keep non-online sensors honest as time passes. */
  sensorSeen: { name: string; lastSeenAt: number | "live" }[];
}

export function buildDataset(now = Date.now()): DemoDataset {
  const rng = createRng(20261002);
  const ext = () => `${rng.pick(EXTERNAL_PREFIXES)}.${rng.int(2, 253)}`;
  const internal = (sensorIdx: number) => `${SENSOR_DEFS[sensorIdx].ip.split(".").slice(0, 3).join(".")}.${rng.int(30, 220)}`;
  const sensorWeights = SENSOR_DEFS.map((s, i) => ({ item: i, weight: s.weight }));

  // Sensors: two healthy, one late (warning), one silent (offline). Status is derived, never assigned.
  const lastSeenAt = [now - 4_000, now - 14_000, now - 5 * 60_000, now - 3 * 3_600_000];
  const sensors: Sensor[] = SENSOR_DEFS.map((d, i) => ({
    id: i + 1, name: d.name, hostname: d.hostname, os: d.os, ip: d.ip, snort_version: d.snort_version,
    last_seen: new Date(lastSeenAt[i]).toISOString(),
    status: deriveSensorStatus(new Date(lastSeenAt[i]).toISOString(), now),
  }));
  const sensorSeen = SENSOR_DEFS.map((d, i) => ({ name: d.name, lastSeenAt: i < 2 ? ("live" as const) : lastSeenAt[i] }));

  const payloadRules = RULES.filter((r) => r.payload);
  const statusDist: { item: PayloadStatus; weight: number }[] = [
    { item: "MALICIOUS", weight: 36 }, { item: "CLEAN", weight: 20 }, { item: "UNKNOWN", weight: 22 },
    { item: "SUSPICIOUS", weight: 16 }, { item: "ERROR", weight: 6 },
  ];

  // Payloads
  const payloads: Payload[] = [];
  const seenHashes = new Set<string>();
  for (let i = 0; i < PAYLOAD_COUNT; i++) {
    let sha = rng.hex(64);
    while (seenHashes.has(sha)) sha = rng.hex(64);
    seenHashes.add(sha);
    const rule = rng.weighted(payloadRules.map((r) => ({ item: r, weight: r.weight })));
    const sIdx = rng.weighted(sensorWeights);
    const ft = rng.pick(FILE_TYPES);
    const first = now - Math.pow(rng.next(), 1.6) * (SPAN_DAYS - 0.2) * DAY - 20 * 60_000;
    const last = Math.min(now - 30_000, first + rng.next() * 3 * DAY);
    const status = rng.weighted(statusDist);
    const total = rng.int(68, 74);
    let mal: number | null = null, sus: number | null = null, und: number | null = null, tot: number | null = null, checked: string | null = null;
    if (status === "MALICIOUS") { mal = rng.int(14, 58); sus = rng.int(0, 6); }
    if (status === "SUSPICIOUS") { mal = rng.int(0, 3); sus = rng.int(3, 9); }
    if (status === "CLEAN") { mal = 0; sus = 0; }
    if (mal !== null && sus !== null) {
      tot = total; und = total - mal - sus;
      checked = new Date(Math.min(now - 60_000, first + rng.int(2, 240) * 60_000)).toISOString();
    }
    payloads.push({
      sha256: sha, sensor_id: sIdx + 1, sensor_name: SENSOR_DEFS[sIdx].name,
      first_seen: new Date(first).toISOString(), last_seen: new Date(last).toISOString(),
      size: rng.int(ft.min, ft.max), mime_type: ft.mime,
      filename: rng.next() < 0.7 ? `${rng.pick(ft.names)}.${ft.ext}` : null,
      status, snort_rule: rule.msg, signature_id: rule.sid,
      vt_malicious: mal, vt_suspicious: sus, vt_undetected: und, vt_total: tot, vt_last_checked: checked,
      vt_submitted_at: null, alert_count: 0,
    });
  }

  // Alerts. Each payload gets its first alert, then random alerts fill the remainder.
  const raw: Omit<Alert, "id">[] = [];
  const build = (sIdx: number, ts: number, ruleIdx: number, payload?: Payload, withPayload = true): Omit<Alert, "id"> => {
    const r = RULES[ruleIdx];
    const outbound = OUTBOUND_SIDS.has(r.sid);
    const dport = r.ports.length ? rng.pick(r.ports) : null;
    const eph = r.protocol === "ICMP" ? null : rng.int(1025, 65535);
    const intIp = internal(sIdx);
    const extIp = ext();
    const has = !!payload && withPayload;
    return {
      sensor_id: sIdx + 1, sensor_name: SENSOR_DEFS[sIdx].name,
      timestamp: new Date(ts).toISOString(), signature_id: r.sid, signature: r.msg,
      classification: r.classification, priority: r.priority, severity: r.severity, protocol: r.protocol,
      source_ip: outbound ? intIp : extIp, source_port: outbound ? eph : (r.protocol === "ICMP" ? null : eph),
      destination_ip: outbound ? extIp : intIp, destination_port: dport,
      payload_available: has, payload_hash: has ? payload!.sha256 : null, payload_size: has ? payload!.size : null,
    };
  };

  for (const p of payloads) {
    const ri = RULES.findIndex((r) => r.sid === p.signature_id);
    raw.push(build(p.sensor_id - 1, new Date(p.first_seen).getTime() + 10_000, ri, p));
  }
  const fillRules = RULES.map((r, i) => ({ item: i, weight: r.weight }));
  while (raw.length < ALERT_COUNT) {
    const ri = rng.weighted(fillRules);
    const r = RULES[ri];
    if (r.payload) {
      const candidates = payloads.filter((p) => p.signature_id === r.sid);
      const p = rng.pick(candidates);
      const a = new Date(p.first_seen).getTime(), b = new Date(p.last_seen).getTime();
      const ts = a + rng.next() * Math.max(b - a, 60_000);
      // Some alerts for payload-capable rules have no captured file: the UI must not assume one exists.
      raw.push(build(p.sensor_id - 1, Math.min(ts, now - 5_000), ri, p, rng.next() > 0.18));
    } else {
      const ts = now - Math.pow(rng.next(), 1.35) * SPAN_DAYS * DAY;
      raw.push(build(rng.weighted(sensorWeights), ts, ri));
    }
  }
  raw.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  const alerts: Alert[] = raw.map((a, i) => ({ ...a, id: i + 1 }));

  const counts = new Map<string, number>();
  for (const a of alerts) if (a.payload_hash) counts.set(a.payload_hash, (counts.get(a.payload_hash) ?? 0) + 1);
  for (const p of payloads) p.alert_count = counts.get(p.sha256) ?? 0;

  return { sensors, alerts, payloads, sensorSeen };
}
