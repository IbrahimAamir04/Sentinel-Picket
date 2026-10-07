import type {
  Alert, AuthUser, DashboardStats, FilterOptions, ListQuery, Meta, Paginated, Payload, PayloadSummary,
  PayloadTrendPoint, ProtocolSlice, RuleCount, Sensor, TimelinePoint, TimelineRange, VtActionResult,
} from "../types";
import { ApiError, type AuthApi, type SentinelApi } from "./api";

/**
 * HTTP implementation of SentinelApi for the Django REST backend.
 * Same-origin by default ("/api", proxied by Vite in development), session cookie + CSRF header.
 * No credential or API key is ever stored in JavaScript.
 */
const BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? "/api";
export const UNAUTHORIZED_EVENT = "sentinel:unauthorized";

const timeZone = () => Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";

function cookie(name: string): string | null {
  const m = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return m ? decodeURIComponent(m[1]) : null;
}

function describe(status: number, body: unknown): string {
  if (status === 429) return "Too many requests. Wait a moment and try again.";
  if (status === 403) return (body as { detail?: string })?.detail ?? "You don't have permission to do this.";
  if (body && typeof body === "object") {
    const b = body as Record<string, unknown>;
    if (typeof b.detail === "string") return b.detail;
    const parts = Object.entries(b).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(" ") : String(v)}`);
    if (parts.length) return parts.join("; ");
  }
  if (status >= 500) return "The server hit an error. Try again, and check the server logs if it keeps happening.";
  return `Request failed (${status}).`;
}

type Params = Record<string, string | number | boolean | undefined | null>;

async function request<T>(path: string, opts: { method?: string; params?: Params; body?: unknown; auth?: boolean } = {}): Promise<T> {
  const method = opts.method ?? "GET";
  const url = new URL(`${BASE}${path}`, window.location.origin);
  for (const [k, v] of Object.entries(opts.params ?? {})) {
    if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v));
  }
  const headers: Record<string, string> = { Accept: "application/json" };
  if (method !== "GET") {
    if (!cookie("csrftoken")) await fetch(`${BASE}/auth/csrf`, { credentials: "same-origin" });
    const token = cookie("csrftoken");
    if (token) headers["X-CSRFToken"] = token;
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  }

  let res: Response;
  try {
    res = await fetch(url, { method, headers, credentials: "same-origin", body: opts.body === undefined ? undefined : JSON.stringify(opts.body) });
  } catch {
    throw new ApiError("Can't reach the Sentinel server. Check that the backend is running and try again.", 0);
  }
  if (res.status === 204) return undefined as T;

  let body: unknown = null;
  try { body = await res.json(); } catch { /* non-JSON error page */ }
  if (!res.ok) {
    if (res.status === 401 && opts.auth !== false) window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
    throw new ApiError(describe(res.status, body), res.status);
  }
  return body as T;
}

const get = <T,>(path: string, params?: Params) => request<T>(path, { params });

/** The date inputs give local calendar days; the server wants instants. */
function dayBounds(q: ListQuery): ListQuery {
  const out = { ...q };
  if (typeof out.date_from === "string" && /^\d{4}-\d{2}-\d{2}$/.test(out.date_from)) out.date_from = new Date(`${out.date_from}T00:00:00`).toISOString();
  if (typeof out.date_to === "string" && /^\d{4}-\d{2}-\d{2}$/.test(out.date_to)) out.date_to = new Date(`${out.date_to}T23:59:59.999`).toISOString();
  return out;
}

export const httpApi: SentinelApi = {
  meta: () => request<Meta>("/meta", { auth: false }),
  dashboardStats: () => get<DashboardStats>("/dashboard/stats"),
  dashboardTimeline: (range: TimelineRange) => get<TimelinePoint[]>("/dashboard/timeline", { range, tz: timeZone() }),
  dashboardProtocols: () => get<ProtocolSlice[]>("/dashboard/protocols"),
  dashboardRules: (limit = 8) => get<RuleCount[]>("/dashboard/rules", { limit }),
  listAlerts: (q) => get<Paginated<Alert>>("/alerts", dayBounds(q) as Params),
  getAlert: (id) => get<Alert>(`/alerts/${id}`),
  listSensors: () => get<Sensor[]>("/sensors"),
  filterOptions: () => get<FilterOptions>("/dashboard/filters"),
  listPayloads: (q) => get<Paginated<Payload>>("/payloads", q as Params),
  getPayload: (sha256) => get<Payload>(`/payloads/${sha256}`),
  payloadSummary: () => get<PayloadSummary>("/payloads/summary"),
  payloadTrend: () => get<PayloadTrendPoint[]>("/payloads/trend", { tz: timeZone() }),

  async checkVirusTotal(sha256) {
    // The server answers 501 until the VirusTotal integration exists; that message is shown to the user as is.
    await request<unknown>(`/payloads/${sha256}/rescan`, { method: "POST" });
    const payload = await get<Payload>(`/payloads/${sha256}`);
    return { payload, simulated: false, message: "VirusTotal hash lookup finished." } satisfies VtActionResult;
  },
  async submitForAnalysis() {
    throw new ApiError("Submitting files to VirusTotal is not available on this server yet.", 501);
  },
};

export const httpAuth: AuthApi = {
  async me() {
    try {
      return await request<AuthUser>("/auth/me", { auth: false });
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) return null;
      throw e;
    }
  },
  async login(username, password) {
    await fetch(`${BASE}/auth/csrf`, { credentials: "same-origin" }).catch(() => undefined);
    return request<AuthUser>("/auth/login", { method: "POST", body: { username, password }, auth: false });
  },
  async logout() {
    await request<void>("/auth/logout", { method: "POST" });
  },
};
