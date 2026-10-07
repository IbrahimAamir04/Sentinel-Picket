import { PageHeader } from "../components/layout/PageHeader";
import { PayloadTrendChart } from "../components/charts/PayloadTrendChart";
import { PayloadDrawer } from "../components/payloads/PayloadDrawer";
import { PayloadsList } from "../components/payloads/PayloadsList";
import { AsyncBoundary } from "../components/ui/AsyncBoundary";
import { Card } from "../components/ui/Card";
import { FilterBar, SearchBox, SelectFilter } from "../components/ui/Controls";
import { Pagination } from "../components/ui/Pagination";
import { StatCard } from "../components/ui/StatCard";
import { EmptyState, ErrorState, LoadingBlock } from "../components/ui/States";
import { useAsync } from "../hooks/useAsync";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { useListParams } from "../hooks/useListParams";
import { useSearchInput } from "../hooks/useSearchInput";
import { api } from "../services";
import { PAYLOAD_STATUSES, label } from "../utils/constants";

const FILTER_KEYS = ["search", "status", "sensor"] as const;

export default function Payloads() {
  useDocumentTitle("Payload intelligence");
  const { params, ordering, patch, toggleSort } = useListParams("-first_seen");
  const [search, setSearch] = useSearchInput(params.search ?? "", (v) => patch({ search: v }));

  const summary = useAsync(() => api.payloadSummary(), []);
  const trend = useAsync(() => api.payloadTrend(), []);
  const options = useAsync(() => api.filterOptions(), []);

  const page = Math.max(1, Number(params.page) || 1);
  const query = { ...Object.fromEntries(FILTER_KEYS.map((k) => [k, params[k]])), ordering, page, page_size: 15 };
  const list = useAsync(() => api.listPayloads(query), [JSON.stringify(query)]);

  const canClear = FILTER_KEYS.some((k) => params[k]);
  const sum = summary.data;
  const reloadAll = () => { summary.reload(); trend.reload(); list.reload(); };

  return (
    <>
      <PageHeader title="Payload intelligence" description="Files captured by Snort, with their VirusTotal verdicts." />

      {summary.error ? <Card><ErrorState message={summary.error} onRetry={summary.reload} /></Card> : (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
          <StatCard label="Total payloads" value={sum?.total} loading={!sum} />
          <StatCard label="Malicious" value={sum?.MALICIOUS} tone="text-crit" loading={!sum} />
          <StatCard label="Suspicious" value={sum?.SUSPICIOUS} tone="text-med" loading={!sum} />
          <StatCard label="Clean" value={sum?.CLEAN} tone="text-ok" loading={!sum} />
          <StatCard label="Unknown" value={sum ? sum.UNKNOWN + sum.ERROR : undefined} loading={!sum}
            hint={sum && sum.ERROR ? `includes ${sum.ERROR} failed lookups` : "not checked or not found"} />
        </div>
      )}

      <Card title="Payload trend · last 14 days">
        <AsyncBoundary state={trend} rows={4}>{(d) => <PayloadTrendChart data={d} />}</AsyncBoundary>
      </Card>

      <Card bodyClass="">
        <FilterBar canClear={canClear} onClear={() => { setSearch(""); patch(Object.fromEntries(FILTER_KEYS.map((k) => [k, null]))); }}>
          <SearchBox value={search} onChange={setSearch} placeholder="Search hash, file name, type or rule" />
          <SelectFilter label="Status" allLabel="All statuses" value={params.status ?? ""} onChange={(v) => patch({ status: v })}
            options={PAYLOAD_STATUSES.map((s) => ({ value: s, label: label(s) }))} />
          <SelectFilter label="Sensor" allLabel="All sensors" value={params.sensor ?? ""} onChange={(v) => patch({ sensor: v })}
            options={(options.data?.sensors ?? []).map((s) => ({ value: String(s.id), label: s.name }))} />
        </FilterBar>

        {list.error ? <ErrorState message={list.error} onRetry={list.reload} />
          : !list.data ? <LoadingBlock rows={8} label="Loading payloads" />
          : list.data.count === 0 ? (
            <EmptyState title="No payloads match these filters">
              {canClear ? "Clear a filter or search for a different hash." : "No payloads have been captured yet."}
            </EmptyState>
          ) : (
            <div className={list.loading ? "opacity-60 transition-opacity" : ""}>
              <PayloadsList rows={list.data.results} ordering={ordering} onSort={toggleSort} onOpen={(sha) => patch({ sha256: sha }, true)} />
              <Pagination page={list.data.page} pageSize={list.data.page_size} count={list.data.count} onPage={(p) => patch({ page: p }, true)} />
            </div>
          )}
      </Card>

      <PayloadDrawer sha256={params.sha256 ?? null} onClose={() => patch({ sha256: null }, true)} onChanged={reloadAll} />
    </>
  );
}
