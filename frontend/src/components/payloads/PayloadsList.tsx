import type { Payload } from "../../types";
import { fmtBytes, fmtShortDateTime, shortHash } from "../../utils/format";
import { PayloadStatusBadge } from "../ui/Badges";
import { SortHeader } from "../ui/SortHeader";

export const vtLabel = (p: Payload) => (p.vt_total == null ? "—" : `${p.vt_malicious}/${p.vt_total}`);

interface Props {
  rows: Payload[];
  ordering: string;
  onSort: (field: string, descFirst?: boolean) => void;
  onOpen: (sha: string) => void;
}

export function PayloadsList({ rows, ordering, onSort, onOpen }: Props) {
  return (
    <>
      <div className="hidden overflow-x-auto md:block">
        <table className="w-full min-w-[56rem] text-sm">
          <thead className="border-b border-line text-xs text-muted">
            <tr>
              <SortHeader field="sha256" ordering={ordering} onSort={onSort}>SHA-256</SortHeader>
              <SortHeader field="first_seen" ordering={ordering} onSort={onSort} descFirst>First seen</SortHeader>
              <SortHeader field="size" ordering={ordering} onSort={onSort} descFirst>Size</SortHeader>
              <SortHeader field="mime_type" ordering={ordering} onSort={onSort}>MIME type</SortHeader>
              <SortHeader field="sensor" ordering={ordering} onSort={onSort}>Sensor</SortHeader>
              <SortHeader field="snort_rule" ordering={ordering} onSort={onSort}>Snort rule</SortHeader>
              <SortHeader field="vt_detection" ordering={ordering} onSort={onSort} descFirst>VT detection</SortHeader>
              <SortHeader field="status" ordering={ordering} onSort={onSort}>Status</SortHeader>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {rows.map((p) => (
              <tr key={p.sha256} className="cursor-pointer hover:bg-raised/60" onClick={() => onOpen(p.sha256)}>
                <td className="px-3 py-2">
                  <button className="whitespace-nowrap font-mono text-xs text-fg hover:text-accent" title={p.sha256} onClick={(e) => { e.stopPropagation(); onOpen(p.sha256); }}>{shortHash(p.sha256)}</button>
                </td>
                <td className="whitespace-nowrap px-3 py-2 text-muted">{fmtShortDateTime(p.first_seen)}</td>
                <td className="whitespace-nowrap px-3 py-2 tabular-nums">{fmtBytes(p.size)}</td>
                <td className="max-w-[11rem] truncate px-3 py-2 font-mono text-xs text-muted" title={p.mime_type}>{p.mime_type}</td>
                <td className="whitespace-nowrap px-3 py-2 text-muted">{p.sensor_name}</td>
                <td className="max-w-[15rem] truncate px-3 py-2" title={p.snort_rule}>{p.snort_rule}</td>
                <td className="whitespace-nowrap px-3 py-2 tabular-nums">{vtLabel(p)}</td>
                <td className="px-3 py-2"><PayloadStatusBadge status={p.status} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <ul className="divide-y divide-line md:hidden">
        {rows.map((p) => (
          <li key={p.sha256}>
            <button onClick={() => onOpen(p.sha256)} className="block w-full space-y-1.5 px-4 py-3 text-left hover:bg-raised/60">
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs text-fg">{shortHash(p.sha256)}</span>
                <PayloadStatusBadge status={p.status} />
              </div>
              <div className="text-sm text-fg">{p.snort_rule}</div>
              <div className="flex flex-wrap gap-x-3 text-xs text-muted">
                <span>{fmtBytes(p.size)}</span><span>VT {vtLabel(p)}</span><span>{p.sensor_name}</span>
              </div>
              <div className="text-xs text-faint">{fmtShortDateTime(p.first_seen)}</div>
            </button>
          </li>
        ))}
      </ul>
    </>
  );
}
