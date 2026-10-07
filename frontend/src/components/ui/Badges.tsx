import type { PayloadStatus, SensorStatus, Severity } from "../../types";
import { label } from "../../utils/constants";

const SEV: Record<Severity, string> = {
  CRITICAL: "text-crit bg-crit/10 border-crit/30",
  HIGH: "text-high bg-high/10 border-high/30",
  MEDIUM: "text-med bg-med/10 border-med/30",
  LOW: "text-low bg-low/10 border-low/30",
};
const PAY: Record<PayloadStatus, string> = {
  MALICIOUS: "text-crit bg-crit/10 border-crit/30",
  SUSPICIOUS: "text-med bg-med/10 border-med/30",
  CLEAN: "text-ok bg-ok/10 border-ok/30",
  UNKNOWN: "text-muted bg-raised border-line-strong",
  ERROR: "text-[#b58ae0] bg-[#a06bd6]/10 border-[#a06bd6]/30",
};
const SENSOR_DOT: Record<SensorStatus, string> = { ONLINE: "bg-ok", WARNING: "bg-med", OFFLINE: "bg-crit" };
const SENSOR_TEXT: Record<SensorStatus, string> = { ONLINE: "text-ok", WARNING: "text-med", OFFLINE: "text-crit" };

const base = "inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-medium leading-none whitespace-nowrap";

export const SeverityBadge = ({ severity }: { severity: Severity }) => (
  <span className={`${base} ${SEV[severity]}`}>{label(severity)}</span>
);

export const PayloadStatusBadge = ({ status }: { status: PayloadStatus }) => (
  <span className={`${base} ${PAY[status]}`}>{label(status)}</span>
);

export const SensorStatusDot = ({ status }: { status: SensorStatus }) => (
  <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${SENSOR_TEXT[status]}`}>
    <span className={`h-2 w-2 rounded-full ${SENSOR_DOT[status]}`} aria-hidden />
    {label(status)}
  </span>
);
