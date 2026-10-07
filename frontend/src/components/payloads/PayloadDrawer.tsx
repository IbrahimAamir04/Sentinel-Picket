import { CloudUpload, Search } from "lucide-react";
import { useEffect, useState } from "react";
import { api, dataMode } from "../../services";
import { useAuth } from "../../auth/AuthContext";
import { hasRole } from "../../auth/roles";
import { useMeta } from "../../meta/MetaContext";
import { useAsync } from "../../hooks/useAsync";
import type { Payload } from "../../types";
import { fmtBytes, fmtDateTime } from "../../utils/format";
import { PayloadStatusBadge } from "../ui/Badges";
import { ConfirmDialog, Notice } from "../ui/ConfirmDialog";
import { CopyButton } from "../ui/CopyButton";
import { DetailList, DetailRow, Drawer } from "../ui/Drawer";
import { ErrorState, LoadingBlock } from "../ui/States";
import { VtResult } from "./VtResult";

type Busy = null | "lookup" | "upload";

export function PayloadDrawer({ sha256, onClose, onChanged }: { sha256: string | null; onClose: () => void; onChanged: () => void }) {
  const { meta } = useMeta();
  const { user } = useAuth();
  const simulated = dataMode === "demo";
  // Why the VirusTotal actions are unavailable, or null when they can run. The server enforces this again on every request.
  const blocked = !meta?.features.virustotal
    ? "VirusTotal lookups aren't enabled on this server yet."
    : !hasRole(user, "ANALYST")
      ? "Checking and submitting payloads needs the analyst or admin role."
      : null;
  const { data, loading, error, reload } = useAsync(() => (sha256 ? api.getPayload(sha256) : Promise.resolve(null)), [sha256]);
  const [p, setP] = useState<Payload | null>(null);
  const [busy, setBusy] = useState<Busy>(null);
  const [notice, setNotice] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
  const [confirmUpload, setConfirmUpload] = useState(false);

  useEffect(() => { setP(data); }, [data]);
  useEffect(() => { setNotice(null); setConfirmUpload(false); }, [sha256]);

  const run = async (kind: Exclude<Busy, null>) => {
    if (!p) return;
    setBusy(kind); setNotice(null);
    try {
      const res = kind === "lookup" ? await api.checkVirusTotal(p.sha256) : await api.submitForAnalysis(p.sha256);
      setP(res.payload);
      setNotice({ tone: "ok", text: res.message });
      onChanged();
    } catch (e) {
      setNotice({ tone: "error", text: e instanceof Error ? e.message : "The request failed." });
    } finally {
      setBusy(null); setConfirmUpload(false);
    }
  };

  return (
    <Drawer open={sha256 != null} onClose={onClose} title="Payload details"
      subtitle={p ? <PayloadStatusBadge status={p.status} /> : undefined}>
      {error ? <ErrorState message={error} onRetry={reload} /> : loading && !p ? <LoadingBlock rows={8} label="Loading payload" /> : !p ? null : (
        <>
          <DetailList>
            <DetailRow label="SHA-256">
              <div className="flex items-start gap-1">
                <span className="break-all font-mono text-xs leading-5">{p.sha256}</span>
                <CopyButton value={p.sha256} label="Copy SHA-256" />
              </div>
            </DetailRow>
            <DetailRow label="File name">{p.filename ?? <span className="text-muted">Not recorded</span>}</DetailRow>
            <DetailRow label="Size">{fmtBytes(p.size)}</DetailRow>
            <DetailRow label="MIME type"><span className="font-mono text-xs">{p.mime_type}</span></DetailRow>
            <DetailRow label="Sensor">{p.sensor_name}</DetailRow>
            <DetailRow label="Snort rule">{p.snort_rule}<div className="font-mono text-xs text-muted">SID {p.signature_id}</div></DetailRow>
            <DetailRow label="First seen">{fmtDateTime(p.first_seen)}</DetailRow>
            <DetailRow label="Last seen">{fmtDateTime(p.last_seen)}</DetailRow>
            <DetailRow label="Related alerts">{p.alert_count}</DetailRow>
          </DetailList>

          <section className="space-y-3 border-t border-line p-4" aria-label="VirusTotal">
            <h3 className="text-sm font-semibold text-fg">VirusTotal result</h3>
            <VtResult p={p} />
          </section>

          <section className="space-y-3 border-t border-line p-4" aria-label="VirusTotal actions">
            {simulated && <Notice tone="info">Demo mode: both actions below are simulated. Nothing is sent to VirusTotal.</Notice>}
            {!simulated && blocked && <Notice tone="info">{blocked}</Notice>}
            {notice && <Notice tone={notice.tone}>{notice.text}</Notice>}

            <div className="rounded-md border border-line p-3">
              <div className="flex items-start gap-3">
                <Search className="mt-0.5 h-4 w-4 shrink-0 text-accent" aria-hidden />
                <div className="flex-1 space-y-2">
                  <div>
                    <p className="text-sm font-medium text-fg">Check VirusTotal hash</p>
                    <p className="text-xs text-muted">Looks up the SHA-256 only. The file itself is never uploaded.</p>
                  </div>
                  <button onClick={() => run("lookup")} disabled={busy !== null || !!blocked}
                    className="h-9 rounded-md border border-line-strong px-3 text-sm hover:bg-raised disabled:opacity-50">
                    {busy === "lookup" ? "Checking…" : "Check hash"}
                  </button>
                </div>
              </div>
            </div>

            <div className="rounded-md border border-high/40 p-3">
              <div className="flex items-start gap-3">
                <CloudUpload className="mt-0.5 h-4 w-4 shrink-0 text-high" aria-hidden />
                <div className="flex-1 space-y-2">
                  <div>
                    <p className="text-sm font-medium text-fg">Submit payload for analysis</p>
                    <p className="text-xs text-muted">Uploads the file to VirusTotal, a third-party service. Only use this for files you are allowed to share externally.</p>
                  </div>
                  <button onClick={() => setConfirmUpload(true)} disabled={busy !== null || !!blocked}
                    className="h-9 rounded-md border border-high/50 px-3 text-sm text-high hover:bg-high/10 disabled:opacity-50">
                    Submit payload…
                  </button>
                </div>
              </div>
            </div>
          </section>

          <ConfirmDialog open={confirmUpload} title="Upload this file to VirusTotal?" confirmLabel="Upload file" busy={busy === "upload"}
            acknowledgement="I understand this file will be submitted to a third party and may become visible to other VirusTotal users."
            onConfirm={() => run("upload")} onCancel={() => setConfirmUpload(false)}>
            <p className="text-muted">The file with hash <span className="font-mono text-xs text-fg">{p.sha256.slice(0, 16)}…</span> would leave your network. A hash check does not do this.</p>
            {simulated && <p className="text-high">Demo mode: this upload is simulated and nothing is sent.</p>}
          </ConfirmDialog>
        </>
      )}
    </Drawer>
  );
}
