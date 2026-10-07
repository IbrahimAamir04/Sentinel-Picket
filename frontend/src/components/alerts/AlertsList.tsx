import { Paperclip } from "lucide-react";
import type { Alert } from "../../types";
import { fmtEndpoint, fmtShortDateTime } from "../../utils/format";
import { SeverityBadge } from "../ui/Badges";
import { SortHeader } from "../ui/SortHeader";

interface Props {
  rows: Alert[];
  ordering: string;
  onSort: (field: string, descFirst?: boolean) => void;
  onOpen: (id: number) => void;
}

/** Table on md+, stacked cards below. Both open the same detail drawer. */
export function AlertsList({ rows, ordering, onSort, onOpen }: Props) {
  return (
    <>
      <div className="hidden overflow-x-auto md:block">
        <table className="w-full min-w-[60rem] text-sm">
          <thead className="border-b border-line text-xs text-muted">
            <tr>
              <SortHeader field="timestamp" ordering={ordering} onSort={onSort} descFirst>Time</SortHeader>
              <SortHeader field="severity" ordering={ordering} onSort={onSort} descFirst>Severity</SortHeader>
              <SortHeader field="signature" ordering={ordering} onSort={onSort}>Rule</SortHeader>
              <SortHeader field="classification" ordering={ordering} onSort={onSort}>Classification</SortHeader>
              <SortHeader field="source_ip" ordering={ordering} onSort={onSort}>Source</SortHeader>
              <SortHeader field="destination_ip" ordering={ordering} onSort={onSort}>Destination</SortHeader>
              <SortHeader field="protocol" ordering={ordering} onSort={onSort}>Protocol</SortHeader>
              <SortHeader field="sensor" ordering={ordering} onSort={onSort}>Sensor</SortHeader>
              <SortHeader field="payload" ordering={ordering} onSort={onSort} descFirst>Payload</SortHeader>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {rows.map((a) => (
              <tr key={a.id} className="cursor-pointer hover:bg-raised/60" onClick={() => onOpen(a.id)}>
                <td className="whitespace-nowrap px-3 py-2 text-muted">{fmtShortDateTime(a.timestamp)}</td>
                <td className="px-3 py-2"><SeverityBadge severity={a.severity} /></td>
                <td className="max-w-[18rem] px-3 py-2">
                  <button className="block max-w-full truncate text-left text-fg hover:text-accent" onClick={(e) => { e.stopPropagation(); onOpen(a.id); }}>{a.signature}</button>
                </td>
                <td className="whitespace-nowrap px-3 py-2 text-muted">{a.classification}</td>
                <td className="whitespace-nowrap px-3 py-2 font-mono text-xs">{fmtEndpoint(a.source_ip, a.source_port)}</td>
                <td className="whitespace-nowrap px-3 py-2 font-mono text-xs">{fmtEndpoint(a.destination_ip, a.destination_port)}</td>
                <td className="px-3 py-2">{a.protocol}</td>
                <td className="whitespace-nowrap px-3 py-2 text-muted">{a.sensor_name}</td>
                <td className="px-3 py-2">
                  {a.payload_available ? <span className="inline-flex items-center gap-1 text-ok"><Paperclip className="h-3.5 w-3.5" aria-hidden />Yes</span> : <span className="text-faint">None</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <ul className="divide-y divide-line md:hidden">
        {rows.map((a) => (
          <li key={a.id}>
            <button onClick={() => onOpen(a.id)} className="block w-full space-y-1.5 px-4 py-3 text-left hover:bg-raised/60">
              <div className="flex items-center justify-between gap-2">
                <SeverityBadge severity={a.severity} />
                <span className="text-xs text-muted">{fmtShortDateTime(a.timestamp)}</span>
              </div>
              <div className="text-sm text-fg">{a.signature}</div>
              <div className="font-mono text-xs text-muted">{fmtEndpoint(a.source_ip, a.source_port)} → {fmtEndpoint(a.destination_ip, a.destination_port)}</div>
              <div className="flex items-center justify-between text-xs text-muted">
                <span>{a.protocol} · {a.sensor_name}</span>
                {a.payload_available && <span className="inline-flex items-center gap-1 text-ok"><Paperclip className="h-3 w-3" aria-hidden />Payload</span>}
              </div>
            </button>
          </li>
        ))}
      </ul>
    </>
  );
}
