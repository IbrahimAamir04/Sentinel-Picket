import type { Payload } from "../../types";
import { fmtDateTime } from "../../utils/format";

/** Detection ratio and breakdown bar. Renders an explicit "no result" state instead of zeros. */
export function VtResult({ p }: { p: Payload }) {
  if (p.vt_total == null) {
    return (
      <div className="space-y-1 text-sm">
        <p className="text-muted">
          {p.vt_last_checked
            ? "VirusTotal has no record of this hash. The file has not been analysed."
            : p.status === "ERROR"
              ? "The last lookup failed. Run the hash check again."
              : "No VirusTotal result yet. Run a hash check to look this file up."}
        </p>
        {p.vt_last_checked && <p className="text-xs text-faint">Last checked {fmtDateTime(p.vt_last_checked)}</p>}
        {p.vt_submitted_at && <p className="text-xs text-faint">Submitted for analysis {fmtDateTime(p.vt_submitted_at)}</p>}
      </div>
    );
  }
  const mal = p.vt_malicious ?? 0, sus = p.vt_suspicious ?? 0, und = p.vt_undetected ?? 0;
  const pct = (n: number) => `${(n / p.vt_total!) * 100}%`;
  return (
    <div className="space-y-2">
      <div className="flex items-baseline gap-2">
        <span className="text-2xl font-semibold tabular-nums text-fg">{mal}<span className="text-muted">/{p.vt_total}</span></span>
        <span className="text-sm text-muted">engines flagged this file as malicious</span>
      </div>
      <div className="flex h-2 overflow-hidden rounded bg-raised" role="img" aria-label={`${mal} malicious, ${sus} suspicious, ${und} undetected`}>
        <div style={{ width: pct(mal), background: "#f0524f" }} />
        <div style={{ width: pct(sus), background: "#e3b341" }} />
        <div style={{ width: pct(und), background: "#34c38f", opacity: 0.55 }} />
      </div>
      <dl className="flex flex-wrap gap-x-5 gap-y-1 text-xs text-muted">
        <div><dt className="inline">Malicious </dt><dd className="inline tabular-nums text-fg">{mal}</dd></div>
        <div><dt className="inline">Suspicious </dt><dd className="inline tabular-nums text-fg">{sus}</dd></div>
        <div><dt className="inline">Undetected </dt><dd className="inline tabular-nums text-fg">{und}</dd></div>
      </dl>
      <p className="text-xs text-faint">Last checked {fmtDateTime(p.vt_last_checked)}</p>
    </div>
  );
}
