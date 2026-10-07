import { Paperclip } from "lucide-react";
import type { Alert } from "../../types";
import { fmtEndpoint, fmtRelative } from "../../utils/format";
import { useNow } from "../../hooks/useNow";
import { SeverityBadge } from "../ui/Badges";

export function RecentAlerts({ alerts, onOpen }: { alerts: Alert[]; onOpen: (id: number) => void }) {
  const now = useNow(5000);
  return (
    <ul className="divide-y divide-line">
      {alerts.map((a) => (
        <li key={a.id}>
          <button onClick={() => onOpen(a.id)} className="flex w-full items-start gap-3 px-4 py-2.5 text-left hover:bg-raised/60">
            <div className="pt-0.5"><SeverityBadge severity={a.severity} /></div>
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm text-fg">{a.signature}</div>
              <div className="truncate font-mono text-xs text-muted">{fmtEndpoint(a.source_ip, a.source_port)} → {fmtEndpoint(a.destination_ip, a.destination_port)}</div>
            </div>
            <div className="flex shrink-0 flex-col items-end gap-1 text-xs text-muted">
              <span>{fmtRelative(a.timestamp, now)}</span>
              {a.payload_available && <Paperclip className="h-3 w-3 text-ok" aria-label="Payload available" />}
            </div>
          </button>
        </li>
      ))}
    </ul>
  );
}
