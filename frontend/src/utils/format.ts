const dtf = new Intl.DateTimeFormat(undefined, {
  year: "numeric", month: "short", day: "2-digit",
  hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
});
const tf = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", hour12: false });
const df = new Intl.DateTimeFormat(undefined, { month: "short", day: "2-digit" });

export const fmtDateTime = (iso: string | null | undefined) => (iso ? dtf.format(new Date(iso)) : "—");
const stf = new Intl.DateTimeFormat(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
/** Compact timestamp for table cells. Drawers show the full date with year. */
export const fmtShortDateTime = (iso: string) => stf.format(new Date(iso));
export const fmtTime = (iso: string) => tf.format(new Date(iso));
export const fmtDay = (iso: string) => df.format(new Date(iso));
export const fmtNumber = (n: number) => n.toLocaleString();
export const fmtPercent = (ratio: number) => `${(ratio * 100).toFixed(1)}%`;

export function fmtBytes(bytes: number | null | undefined): string {
  if (bytes == null) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let v = bytes / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

export function fmtRelative(iso: string, now = Date.now()): string {
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.floor(h / 24)} d ago`;
}

export const shortHash = (h: string | null | undefined) => (h ? `${h.slice(0, 10)}…${h.slice(-6)}` : "—");
export const fmtEndpoint = (ip: string, port: number | null) => (port != null ? `${ip}:${port}` : ip);
