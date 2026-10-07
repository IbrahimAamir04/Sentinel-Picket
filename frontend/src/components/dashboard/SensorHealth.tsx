import { Monitor, Terminal } from "lucide-react";
import type { Sensor } from "../../types";
import { fmtRelative } from "../../utils/format";
import { useNow } from "../../hooks/useNow";
import { SensorStatusDot } from "../ui/Badges";
import { WARNING_AFTER_SECONDS, OFFLINE_AFTER_SECONDS } from "../../utils/sensorStatus";

export function SensorHealth({ sensors }: { sensors: Sensor[] }) {
  const now = useNow(1000);
  return (
    <div className="space-y-2">
      <ul className="divide-y divide-line">
        {sensors.map((s) => {
          const OsIcon = s.os === "LINUX" ? Terminal : Monitor;
          return (
            <li key={s.id} title={[s.hostname, s.ip].filter(Boolean).join(" · ") || undefined} className="flex items-center justify-between gap-3 py-2.5">
              <div className="flex min-w-0 items-center gap-2.5">
                <OsIcon className="h-4 w-4 shrink-0 text-muted" aria-hidden />
                <div className="min-w-0">
                  <div className="truncate text-sm text-fg">{s.name}</div>
                  <div className="truncate text-xs text-muted">{s.os === "LINUX" ? "Linux" : "Windows"} · {s.snort_version ? `Snort ${s.snort_version}` : "Snort version not reported"}</div>
                </div>
              </div>
              <div className="shrink-0 text-right">
                <SensorStatusDot status={s.status} />
                <div className="text-xs text-faint">{s.last_seen ? `seen ${fmtRelative(s.last_seen, now)}` : "never reported"}</div>
              </div>
            </li>
          );
        })}
      </ul>
      <p className="text-xs text-faint">Status comes from last heartbeat: warning after {WARNING_AFTER_SECONDS / 60} min, offline after {OFFLINE_AFTER_SECONDS / 60} min.</p>
    </div>
  );
}
