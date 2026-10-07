import { RefreshCw } from "lucide-react";
import { fmtRelative } from "../../utils/format";
import { useNow } from "../../hooks/useNow";

export function RefreshStatus({ updatedAt, refreshing, failed, auto, onAuto, onRefresh, intervalSec }: {
  updatedAt: number | null; refreshing: boolean; failed: boolean; auto: boolean; intervalSec: number;
  onAuto: (v: boolean) => void; onRefresh: () => void;
}) {
  const now = useNow(1000);
  return (
    <div className="flex flex-wrap items-center gap-3 text-xs text-muted">
      <span role="status" className={failed ? "text-crit" : ""}>
        {failed ? "Last refresh failed" : updatedAt ? `Updated ${fmtRelative(new Date(updatedAt).toISOString(), now)}` : "Loading…"}
      </span>
      <label className="flex cursor-pointer items-center gap-1.5">
        <input type="checkbox" checked={auto} onChange={(e) => onAuto(e.target.checked)} className="h-3.5 w-3.5 accent-[#4aa8ff]" />
        Auto-refresh {intervalSec}s
      </label>
      <button onClick={onRefresh} disabled={refreshing} className="inline-flex h-8 items-center gap-1.5 rounded-md border border-line-strong px-2.5 text-sm text-fg hover:bg-raised disabled:opacity-60">
        <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} aria-hidden /> Refresh
      </button>
    </div>
  );
}
