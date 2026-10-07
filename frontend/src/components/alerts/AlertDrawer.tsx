import { ExternalLink, FileX2, Paperclip } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../../services";
import { useAsync } from "../../hooks/useAsync";
import { fmtBytes, fmtDateTime } from "../../utils/format";
import { CopyButton } from "../ui/CopyButton";
import { DetailList, DetailRow, Drawer } from "../ui/Drawer";
import { SeverityBadge } from "../ui/Badges";
import { ErrorState, LoadingBlock } from "../ui/States";

/** Rendered as React text only. Snort fields are untrusted and are never injected as HTML. */
export function AlertDrawer({ alertId, onClose }: { alertId: number | null; onClose: () => void }) {
  const { data: a, loading, error, reload } = useAsync(() => (alertId == null ? Promise.resolve(null) : api.getAlert(alertId)), [alertId]);

  return (
    <Drawer open={alertId != null} onClose={onClose} title={a ? a.signature : "Alert details"}
      subtitle={a ? <span className="flex items-center gap-2"><SeverityBadge severity={a.severity} /> Alert #{a.id}</span> : undefined}>
      {error ? <ErrorState message={error} onRetry={reload} /> : loading || !a ? <LoadingBlock rows={8} label="Loading alert" /> : (
        <>
          <DetailList>
            <DetailRow label="Severity"><SeverityBadge severity={a.severity} /> <span className="ml-2 text-muted">priority {a.priority}</span></DetailRow>
            <DetailRow label="Rule / signature">{a.signature}<div className="font-mono text-xs text-muted">SID {a.signature_id}</div></DetailRow>
            <DetailRow label="Classification">{a.classification}</DetailRow>
            <DetailRow label="Source"><span className="font-mono">{a.source_ip}</span></DetailRow>
            <DetailRow label="Destination"><span className="font-mono">{a.destination_ip}</span></DetailRow>
            <DetailRow label="Ports"><span className="font-mono">{a.source_port ?? "n/a"} → {a.destination_port ?? "n/a"}</span></DetailRow>
            <DetailRow label="Protocol">{a.protocol}</DetailRow>
            <DetailRow label="Sensor">{a.sensor_name}</DetailRow>
            <DetailRow label="Timestamp">{fmtDateTime(a.timestamp)}</DetailRow>
            <DetailRow label="Payload">
              {a.payload_available ? (
                <span className="inline-flex items-center gap-1.5 text-ok"><Paperclip className="h-3.5 w-3.5" aria-hidden />Available · {fmtBytes(a.payload_size)}</span>
              ) : (
                <span className="inline-flex items-center gap-1.5 text-muted"><FileX2 className="h-3.5 w-3.5" aria-hidden />No payload captured for this alert</span>
              )}
            </DetailRow>
            <DetailRow label="SHA-256">
              {a.payload_hash ? (
                <div className="flex items-start gap-1">
                  <span className="break-all font-mono text-xs leading-5">{a.payload_hash}</span>
                  <CopyButton value={a.payload_hash} label="Copy SHA-256" />
                </div>
              ) : <span className="text-muted">Not available</span>}
            </DetailRow>
          </DetailList>
          {a.payload_hash && (
            <div className="border-t border-line p-4">
              <Link to={`/payloads?sha256=${a.payload_hash}`} className="inline-flex h-9 items-center gap-1.5 rounded-md border border-line-strong px-3 text-sm hover:bg-raised">
                <ExternalLink className="h-4 w-4" aria-hidden /> Open in payload intelligence
              </Link>
            </div>
          )}
        </>
      )}
    </Drawer>
  );
}
