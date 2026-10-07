import { ShieldAlert } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";

/** Blocking confirmation for actions with external side effects. Requires an explicit acknowledgement. */
export function ConfirmDialog({ open, title, confirmLabel, acknowledgement, busy, onConfirm, onCancel, children }: {
  open: boolean; title: string; confirmLabel: string; acknowledgement: string; busy?: boolean;
  onConfirm: () => void; onCancel: () => void; children: ReactNode;
}) {
  const [ack, setAck] = useState(false);
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    setAck(false);
    cancelRef.current?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") { e.stopPropagation(); onCancel(); } };
    document.addEventListener("keydown", onKey, true);
    return () => document.removeEventListener("keydown", onKey, true);
  }, [open, onCancel]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-end justify-center p-0 sm:items-center sm:p-4">
      <div className="absolute inset-0 bg-black/70" onClick={busy ? undefined : onCancel} aria-hidden />
      <div role="alertdialog" aria-modal="true" aria-label={title}
        className="relative w-full max-w-md rounded-t-lg border border-high/40 bg-surface p-5 shadow-xl sm:rounded-lg">
        <div className="flex items-start gap-3">
          <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-high" aria-hidden />
          <div className="space-y-3 text-sm">
            <h3 className="text-base font-semibold text-fg">{title}</h3>
            {children}
            <label className="flex cursor-pointer items-start gap-2 text-fg">
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} className="mt-0.5 h-4 w-4 accent-[#4aa8ff]" />
              <span>{acknowledgement}</span>
            </label>
          </div>
        </div>
        <div className="mt-5 flex justify-end gap-2">
          <button ref={cancelRef} onClick={onCancel} disabled={busy}
            className="h-9 rounded-md border border-line-strong px-3 text-sm hover:bg-raised disabled:opacity-50">Cancel</button>
          <button onClick={onConfirm} disabled={!ack || busy}
            className="h-9 rounded-md bg-high px-3 text-sm font-medium text-black hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40">
            {busy ? "Working…" : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

export const Notice = ({ tone, children }: { tone: "info" | "ok" | "error"; children: ReactNode }) => {
  const c = tone === "ok" ? "border-ok/30 bg-ok/10 text-ok" : tone === "error" ? "border-crit/30 bg-crit/10 text-crit" : "border-accent/30 bg-accent/10 text-accent";
  return <div role={tone === "error" ? "alert" : "status"} className={`rounded-md border px-3 py-2 text-sm ${c}`}>{children}</div>;
};
