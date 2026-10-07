export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type SensorStatus = "ONLINE" | "WARNING" | "OFFLINE";
export type SensorOS = "LINUX" | "WINDOWS";
export type PayloadStatus = "UNKNOWN" | "CLEAN" | "SUSPICIOUS" | "MALICIOUS" | "ERROR";

export interface Sensor {
  id: number;
  name: string;
  hostname: string; // reported by the sensor itself; may be empty until its first heartbeat
  os: SensorOS;
  ip: string | null;
  snort_version: string; // empty until the sensor reports it
  status: SensorStatus; // always derived from last_seen
  last_seen: string | null; // ISO; null for a registered sensor that has never reported
}

export interface Alert {
  id: number;
  sensor_id: number;
  sensor_name: string;
  timestamp: string;
  signature_id: number;
  signature: string;
  classification: string;
  priority: number;
  severity: Severity;
  protocol: string;
  source_ip: string;
  source_port: number | null;
  destination_ip: string;
  destination_port: number | null;
  payload_available: boolean;
  payload_hash: string | null;
  payload_size: number | null;
}

export interface Payload {
  sha256: string;
  sensor_id: number;
  sensor_name: string;
  first_seen: string;
  last_seen: string;
  size: number;
  mime_type: string;
  filename: string | null;
  status: PayloadStatus;
  snort_rule: string;
  signature_id: number;
  vt_malicious: number | null;
  vt_suspicious: number | null;
  vt_undetected: number | null;
  vt_total: number | null;
  vt_last_checked: string | null;
  vt_submitted_at: string | null; // set only after an explicit external upload
  alert_count: number;
}

export interface Paginated<T> {
  count: number;
  page: number;
  page_size: number;
  results: T[];
}

export interface ListQuery {
  search?: string;
  ordering?: string; // "-timestamp" style
  page?: number;
  page_size?: number;
  [filter: string]: string | number | undefined;
}

export interface DashboardStats {
  total_alerts: number;
  by_severity: Record<Severity, number>;
  total_payloads: number;
  malicious_payloads: number;
  checked_payloads: number;
  detection_rate: number; // 0..1, malicious / checked
  classifications: { name: string; count: number }[];
}

export type TimelineRange = "24h" | "7d";
export interface TimelinePoint {
  bucket: string; // ISO start of bucket
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
}

export interface ProtocolSlice { protocol: string; count: number }
export interface RuleCount { signature_id: number; signature: string; classification: string; count: number }

export interface PayloadSummary {
  total: number;
  MALICIOUS: number;
  SUSPICIOUS: number;
  CLEAN: number;
  UNKNOWN: number;
  ERROR: number;
}
export interface PayloadTrendPoint {
  day: string;
  MALICIOUS: number;
  SUSPICIOUS: number;
  CLEAN: number;
  UNKNOWN: number;
}

export interface FilterOptions {
  sensors: { id: number; name: string }[];
  protocols: string[];
  rules: { signature_id: number; signature: string }[];
}

export interface Meta {
  mode: "demo" | "live";
  generated_at: string;
  /** What the server can actually do. The UI disables anything that is false instead of faking it. */
  features: { virustotal: boolean; realtime: boolean };
}

export type Role = "ADMIN" | "ANALYST" | "VIEWER";
export interface AuthUser {
  id: number;
  username: string;
  first_name?: string;
  last_name?: string;
  role: Role;
}

/** Result of an explicit, user-triggered VirusTotal action. */
export interface VtActionResult {
  payload: Payload;
  simulated: boolean;
  message: string;
}
