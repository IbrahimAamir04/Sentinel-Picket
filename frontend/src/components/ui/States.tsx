import { AlertTriangle, Inbox, RefreshCw } from "lucide-react";
import type { ReactNode } from "react";

export function LoadingBlock({ rows = 5, label = "Loading" }: { rows?: number; label?: string }) {
  return (
    <div role="status" aria-label={label} className="space-y-2 p-4">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="h-8 animate-pulse rounded bg-raised" style={{ opacity: 1 - i * 0.12 }} />
      ))}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-2 px-6 py-12 text-center">
      <Inbox className="h-8 w-8 text-faint" aria-hidden />
      <p className="font-medium text-fg">{title}</p>
      {children && <p className="max-w-sm text-sm text-muted">{children}</p>}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex flex-col items-center gap-2 px-6 py-10 text-center">
      <AlertTriangle className="h-8 w-8 text-crit" aria-hidden />
      <p className="font-medium text-fg">Couldn’t load this data</p>
      <p className="max-w-md text-sm text-muted">{message}</p>
      {onRetry && (
        <button onClick={onRetry} className="mt-2 inline-flex items-center gap-1.5 rounded-md border border-line-strong px-3 py-1.5 text-sm hover:bg-raised">
          <RefreshCw className="h-3.5 w-3.5" aria-hidden /> Try again
        </button>
      )}
    </div>
  );
}
