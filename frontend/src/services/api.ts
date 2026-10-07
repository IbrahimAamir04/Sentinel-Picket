import type {
  Alert, AuthUser, DashboardStats, FilterOptions, ListQuery, Meta, Paginated, Payload, PayloadSummary,
  PayloadTrendPoint, ProtocolSlice, RuleCount, Sensor, TimelinePoint, TimelineRange, VtActionResult,
} from "../types";

/**
 * Contract between the UI and its data source. It mirrors the planned Django REST API
 * (GET /api/dashboard/*, /api/alerts, /api/payloads, ...). Phase 2 adds an HTTP
 * implementation of this interface; pages and components do not change.
 */
export interface SentinelApi {
  meta(): Promise<Meta>;
  dashboardStats(): Promise<DashboardStats>;
  dashboardTimeline(range: TimelineRange): Promise<TimelinePoint[]>;
  dashboardProtocols(): Promise<ProtocolSlice[]>;
  dashboardRules(limit?: number): Promise<RuleCount[]>;
  listAlerts(q: ListQuery): Promise<Paginated<Alert>>;
  getAlert(id: number): Promise<Alert>;
  listSensors(): Promise<Sensor[]>;
  filterOptions(): Promise<FilterOptions>;
  listPayloads(q: ListQuery): Promise<Paginated<Payload>>;
  getPayload(sha256: string): Promise<Payload>;
  payloadSummary(): Promise<PayloadSummary>;
  payloadTrend(): Promise<PayloadTrendPoint[]>;
  /** Hash lookup only. Sends the SHA-256 to VirusTotal; never uploads file content. */
  checkVirusTotal(sha256: string): Promise<VtActionResult>;
  /** External upload of the file itself to VirusTotal. Must only run after explicit user confirmation. */
  submitForAnalysis(sha256: string): Promise<VtActionResult>;
}

/** Session authentication. Cookies hold the session; the browser never sees a token or any API key. */
export interface AuthApi {
  me(): Promise<AuthUser | null>; // null when signed out
  login(username: string, password: string): Promise<AuthUser>;
  logout(): Promise<void>;
}

export class ApiError extends Error {
  status: number;
  constructor(message: string, status = 500) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}
