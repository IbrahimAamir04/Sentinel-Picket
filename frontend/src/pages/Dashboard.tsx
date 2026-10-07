import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { AlertDrawer } from "../components/alerts/AlertDrawer";
import { ClassificationChart } from "../components/charts/ClassificationChart";
import { ProtocolChart } from "../components/charts/ProtocolChart";
import { TimelineChart } from "../components/charts/TimelineChart";
import { RecentAlerts } from "../components/dashboard/RecentAlerts";
import { RefreshStatus } from "../components/dashboard/RefreshStatus";
import { SensorHealth } from "../components/dashboard/SensorHealth";
import { TopRules } from "../components/dashboard/TopRules";
import { PageHeader } from "../components/layout/PageHeader";
import { AsyncBoundary } from "../components/ui/AsyncBoundary";
import { Card } from "../components/ui/Card";
import { StatCard } from "../components/ui/StatCard";
import { useAsync } from "../hooks/useAsync";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { api } from "../services";
import type { TimelineRange } from "../types";
import { fmtNumber, fmtPercent } from "../utils/format";

const AUTO_SECONDS = 30;

export default function Dashboard() {
  useDocumentTitle("Dashboard");
  const [range, setRange] = useState<TimelineRange>("24h");
  const [auto, setAuto] = useState(true);
  const [sp, setSp] = useSearchParams();
  const alertId = sp.get("alert") ? Number(sp.get("alert")) : null;

  const stats = useAsync(() => api.dashboardStats(), []);
  const timeline = useAsync(() => api.dashboardTimeline(range), [range]);
  const protocols = useAsync(() => api.dashboardProtocols(), []);
  const rules = useAsync(() => api.dashboardRules(8), []);
  const recent = useAsync(() => api.listAlerts({ ordering: "-timestamp", page_size: 8 }), []);
  const sensors = useAsync(() => api.listSensors(), []);

  const all = [stats, timeline, protocols, rules, recent, sensors];
  const refresh = () => all.forEach((s) => s.reload());
  const refreshing = all.some((s) => s.loading);
  const failed = all.some((s) => s.error);
  const updatedAt = Math.max(0, ...all.map((s) => s.updatedAt ?? 0)) || null;

  useEffect(() => {
    if (!auto) return;
    const t = setInterval(refresh, AUTO_SECONDS * 1000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auto, range]);

  const openAlert = (id: number) => setSp({ alert: String(id) });
  const closeAlert = () => setSp({}, { replace: true });
  const s = stats.data;

  return (
    <>
      <PageHeader title="Dashboard" description="Alert activity, payload verdicts and sensor health."
        actions={<RefreshStatus updatedAt={updatedAt} refreshing={refreshing} failed={failed} auto={auto} onAuto={setAuto} onRefresh={refresh} intervalSec={AUTO_SECONDS} />} />

      {stats.error ? (
        <Card><AsyncBoundary state={stats}>{() => null}</AsyncBoundary></Card>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4 2xl:grid-cols-8">
            <StatCard label="Total alerts" value={s && fmtNumber(s.total_alerts)} loading={!s} />
            <StatCard label="Critical" value={s && fmtNumber(s.by_severity.CRITICAL)} tone="text-crit" loading={!s} />
            <StatCard label="High" value={s && fmtNumber(s.by_severity.HIGH)} loading={!s} tone="text-high" />
            <StatCard label="Medium" value={s && fmtNumber(s.by_severity.MEDIUM)} loading={!s} tone="text-med" />
            <StatCard label="Low" value={s && fmtNumber(s.by_severity.LOW)} loading={!s} tone="text-low" />
            <StatCard label="Total payloads" value={s && fmtNumber(s.total_payloads)} loading={!s} />
            <StatCard label="Malicious payloads" value={s && fmtNumber(s.malicious_payloads)} tone="text-crit" loading={!s} />
            <StatCard label="Detection rate" value={s && (s.checked_payloads ? fmtPercent(s.detection_rate) : "—")} loading={!s}
              hint={s ? (s.checked_payloads ? `${s.malicious_payloads} of ${s.checked_payloads} checked` : "no payloads checked yet") : undefined} />
          </div>
        </>
      )}

      <div className="grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2" title="Alert timeline"
          action={
            <div role="group" aria-label="Timeline range" className="flex rounded-md border border-line-strong text-xs">
              {(["24h", "7d"] as const).map((r) => (
                <button key={r} onClick={() => setRange(r)} aria-pressed={range === r}
                  className={`px-2.5 py-1 first:rounded-l-md last:rounded-r-md ${range === r ? "bg-raised text-fg" : "text-muted hover:text-fg"}`}>
                  {r === "24h" ? "24 hours" : "7 days"}
                </button>
              ))}
            </div>
          }>
          <AsyncBoundary state={timeline} rows={5}>{(d) => <TimelineChart data={d} range={range} />}</AsyncBoundary>
        </Card>
        <Card title="Protocol distribution">
          <AsyncBoundary state={protocols} rows={4}>{(d) => <ProtocolChart data={d} />}</AsyncBoundary>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
        <Card title="Threat classification">
          <AsyncBoundary state={stats} rows={5}>{(d) => <ClassificationChart data={d.classifications} />}</AsyncBoundary>
        </Card>
        <Card title="Top Snort rules">
          <AsyncBoundary state={rules} rows={5}>{(d) => <TopRules rules={d} />}</AsyncBoundary>
        </Card>
        <Card title="Sensor health" className="lg:col-span-2 xl:col-span-1">
          <AsyncBoundary state={sensors} rows={4}>{(d) => <SensorHealth sensors={d} />}</AsyncBoundary>
        </Card>
      </div>

      <Card title="Recent alerts" bodyClass="">
        <AsyncBoundary state={recent} rows={6}>{(d) => <RecentAlerts alerts={d.results} onOpen={openAlert} />}</AsyncBoundary>
      </Card>

      <AlertDrawer alertId={alertId} onClose={closeAlert} />
    </>
  );
}

