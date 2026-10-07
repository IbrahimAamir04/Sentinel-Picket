import type { SensorStatus } from "../types";

/** Heartbeat thresholds. The backend (Phase 3) must use the same rule: status is derived from last_seen, never stored by hand. */
export const WARNING_AFTER_SECONDS = 120;
export const OFFLINE_AFTER_SECONDS = 600;

export function deriveSensorStatus(lastSeenIso: string | null, now = Date.now()): SensorStatus {
  if (!lastSeenIso) return "OFFLINE"; // never reported
  const age = (now - new Date(lastSeenIso).getTime()) / 1000;
  if (age >= OFFLINE_AFTER_SECONDS) return "OFFLINE";
  if (age >= WARNING_AFTER_SECONDS) return "WARNING";
  return "ONLINE";
}
