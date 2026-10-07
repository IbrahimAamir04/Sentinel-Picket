import { Check, Copy } from "lucide-react";
import { useState } from "react";

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [done, setDone] = useState(false);
  const [failed, setFailed] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setDone(true); setFailed(false);
      setTimeout(() => setDone(false), 1500);
    } catch {
      setFailed(true);
      setTimeout(() => setFailed(false), 2500);
    }
  };
  return (
    <button type="button" onClick={copy} aria-label={label} title={failed ? "Clipboard is unavailable in this context" : label}
      className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded text-muted hover:bg-raised hover:text-fg">
      {done ? <Check className="h-3.5 w-3.5 text-ok" /> : <Copy className={`h-3.5 w-3.5 ${failed ? "text-crit" : ""}`} />}
    </button>
  );
}
