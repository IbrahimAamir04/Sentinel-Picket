import type { ReactNode } from "react";

export function StatCard({ label, value, hint, tone = "text-fg", loading }: {
  label: string; value: ReactNode; hint?: string; tone?: string; loading?: boolean;
}) {
  return (
    <div className="rounded-lg border border-line bg-surface px-4 py-3" title={hint}>
      <div className="text-xs text-muted">{label}</div>
      {loading ? (
        <div className="mt-2 h-7 w-16 animate-pulse rounded bg-raised" />
      ) : (
        <div className={`mt-1 text-2xl font-semibold tabular-nums ${tone}`}>{value}</div>
      )}
      {hint && <div className="mt-0.5 truncate text-xs text-faint">{hint}</div>}
    </div>
  );
}
