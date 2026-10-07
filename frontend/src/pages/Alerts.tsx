import { AlertDrawer } from "../components/alerts/AlertDrawer";
import { AlertsList } from "../components/alerts/AlertsList";
import { PageHeader } from "../components/layout/PageHeader";
import { Card } from "../components/ui/Card";
import { DateFilter, FilterBar, SearchBox, SelectFilter } from "../components/ui/Controls";
import { Pagination } from "../components/ui/Pagination";
import { EmptyState, ErrorState, LoadingBlock } from "../components/ui/States";
import { useAsync } from "../hooks/useAsync";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { useListParams } from "../hooks/useListParams";
import { useSearchInput } from "../hooks/useSearchInput";
import { api } from "../services";
import { SEVERITIES, label } from "../utils/constants";

const FILTER_KEYS = ["search", "severity", "sensor", "protocol", "rule", "date_from", "date_to"] as const;

export default function Alerts() {
  useDocumentTitle("Snort alerts");
  const { params, ordering, page, patch, toggleSort } = useListParams("-timestamp");
  const [search, setSearch] = useSearchInput(params.search ?? "", (v) => patch({ search: v }));

  const options = useAsync(() => api.filterOptions(), []);
  const query = { ...Object.fromEntries(FILTER_KEYS.map((k) => [k, params[k]])), ordering, page, page_size: 20 };
  const list = useAsync(() => api.listAlerts(query), [JSON.stringify(query)]);

  const alertId = params.alert ? Number(params.alert) : null;
  const canClear = FILTER_KEYS.some((k) => params[k]);
  const opts = options.data;

  return (
    <>
      <PageHeader title="Snort alerts" description="Search, filter and sort every alert received from your sensors." />
      <Card bodyClass="">
        <FilterBar canClear={canClear} onClear={() => { setSearch(""); patch(Object.fromEntries(FILTER_KEYS.map((k) => [k, null]))); }}>
          <SearchBox value={search} onChange={setSearch} placeholder="Search rule, IP, sensor or hash" />
          <SelectFilter label="Severity" allLabel="All severities" value={params.severity ?? ""} onChange={(v) => patch({ severity: v })}
            options={SEVERITIES.map((s) => ({ value: s, label: label(s) }))} />
          <SelectFilter label="Sensor" allLabel="All sensors" value={params.sensor ?? ""} onChange={(v) => patch({ sensor: v })}
            options={(opts?.sensors ?? []).map((s) => ({ value: String(s.id), label: s.name }))} />
          <SelectFilter label="Protocol" allLabel="All protocols" value={params.protocol ?? ""} onChange={(v) => patch({ protocol: v })}
            options={(opts?.protocols ?? []).map((p) => ({ value: p, label: p }))} />
          <SelectFilter label="Rule" allLabel="All rules" value={params.rule ?? ""} onChange={(v) => patch({ rule: v })}
            options={(opts?.rules ?? []).map((r) => ({ value: String(r.signature_id), label: r.signature }))} />
          <DateFilter label="From" value={params.date_from ?? ""} onChange={(v) => patch({ date_from: v })} />
          <DateFilter label="To" value={params.date_to ?? ""} onChange={(v) => patch({ date_to: v })} />
        </FilterBar>

        {list.error ? <ErrorState message={list.error} onRetry={list.reload} />
          : !list.data ? <LoadingBlock rows={8} label="Loading alerts" />
          : list.data.count === 0 ? (
            <EmptyState title="No alerts match these filters">
              {canClear ? "Try widening the date range or clearing a filter." : "No alerts have been received yet."}
            </EmptyState>
          ) : (
            <div className={list.loading ? "opacity-60 transition-opacity" : ""}>
              <AlertsList rows={list.data.results} ordering={ordering} onSort={toggleSort} onOpen={(id) => patch({ alert: id }, true)} />
              <Pagination page={list.data.page} pageSize={list.data.page_size} count={list.data.count} onPage={(p) => patch({ page: p }, true)} />
            </div>
          )}
      </Card>
      <AlertDrawer alertId={alertId} onClose={() => patch({ alert: null }, true)} />
    </>
  );
}
