import { Search, X } from "lucide-react";
import type { ReactNode } from "react";

const field = "h-9 rounded-md border border-line-strong bg-bg px-2.5 text-sm text-fg placeholder:text-faint";

export function SearchBox({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <div className="relative min-w-[16rem] flex-1 basis-full sm:basis-72">
      <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-faint" aria-hidden />
      <input type="search" value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} aria-label={placeholder}
        className={`${field} w-full pl-8`} />
    </div>
  );
}

export function SelectFilter({ label, value, onChange, options, allLabel }: {
  label: string; value: string; onChange: (v: string) => void; options: { value: string; label: string }[]; allLabel: string;
}) {
  return (
    <select aria-label={label} value={value} onChange={(e) => onChange(e.target.value)} className={`${field} max-w-[14rem]`}>
      <option value="">{allLabel}</option>
      {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  );
}

export function DateFilter({ label, value, onChange }: { label: string; value: string; onChange: (v: string) => void }) {
  return (
    <label className="flex items-center gap-1.5 text-xs text-muted">
      {label}
      <input type="date" value={value} onChange={(e) => onChange(e.target.value)} className={`${field} [color-scheme:dark]`} />
    </label>
  );
}

export function FilterBar({ children, onClear, canClear }: { children: ReactNode; onClear: () => void; canClear: boolean }) {
  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-line p-3">
      {children}
      {canClear && (
        <button type="button" onClick={onClear} className="inline-flex h-9 items-center gap-1 rounded-md px-2.5 text-sm text-muted hover:bg-raised hover:text-fg">
          <X className="h-4 w-4" aria-hidden /> Clear filters
        </button>
      )}
    </div>
  );
}
