import type { PayloadStatus, Severity } from "../types";

export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
export const PAYLOAD_STATUSES: PayloadStatus[] = ["MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN", "ERROR"];

export const SEVERITY_COLOR: Record<Severity, string> = {
  CRITICAL: "#f0524f",
  HIGH: "#f08a3c",
  MEDIUM: "#e3b341",
  LOW: "#4aa8ff",
};
export const STATUS_COLOR: Record<PayloadStatus, string> = {
  MALICIOUS: "#f0524f",
  SUSPICIOUS: "#e3b341",
  CLEAN: "#34c38f",
  UNKNOWN: "#6b7788",
  ERROR: "#a06bd6",
};
export const label = (v: string) => v.charAt(0) + v.slice(1).toLowerCase();
