import type { RuleCount } from "../../types";

export function TopRules({ rules }: { rules: RuleCount[] }) {
  const max = Math.max(1, ...rules.map((r) => r.count));
  return (
    <ol className="space-y-2.5">
      {rules.map((r) => (
        <li key={r.signature_id} className="space-y-1">
          <div className="flex items-baseline justify-between gap-3 text-sm">
            <span className="min-w-0 truncate text-fg" title={r.signature}>{r.signature}</span>
            <span className="shrink-0 tabular-nums text-muted">{r.count}</span>
          </div>
          <div className="h-1 rounded bg-raised"><div className="h-1 rounded bg-accent/70" style={{ width: `${(r.count / max) * 100}%` }} /></div>
        </li>
      ))}
    </ol>
  );
}
