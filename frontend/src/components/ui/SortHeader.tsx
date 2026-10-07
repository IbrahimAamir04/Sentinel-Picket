import { ArrowDown, ArrowUp, ChevronsUpDown } from "lucide-react";

export function SortHeader({ field, ordering, onSort, descFirst, children }: {
  field: string; ordering: string; onSort: (field: string, descFirst?: boolean) => void; descFirst?: boolean; children: string;
}) {
  const active = ordering === field || ordering === `-${field}`;
  const desc = ordering === `-${field}`;
  const Icon = !active ? ChevronsUpDown : desc ? ArrowDown : ArrowUp;
  return (
    <th scope="col" aria-sort={active ? (desc ? "descending" : "ascending") : "none"} className="px-3 py-2 text-left font-medium whitespace-nowrap">
      <button type="button" onClick={() => onSort(field, descFirst)} className={`inline-flex items-center gap-1 hover:text-fg ${active ? "text-fg" : ""}`}>
        {children}
        <Icon className={`h-3 w-3 ${active ? "" : "opacity-40"}`} aria-hidden />
      </button>
    </th>
  );
}
