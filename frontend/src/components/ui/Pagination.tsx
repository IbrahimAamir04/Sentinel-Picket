import { ChevronLeft, ChevronRight } from "lucide-react";

export function Pagination({ page, pageSize, count, onPage }: {
  page: number; pageSize: number; count: number; onPage: (p: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(count / pageSize));
  const from = count === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(count, page * pageSize);
  const btn = "inline-flex h-8 items-center gap-1 rounded-md border border-line-strong px-2.5 text-sm hover:bg-raised disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-transparent";
  return (
    <nav aria-label="Pagination" className="flex flex-wrap items-center justify-between gap-2 border-t border-line px-4 py-2.5 text-sm text-muted">
      <span>{from}–{to} of {count.toLocaleString()}</span>
      <div className="flex items-center gap-2">
        <button className={btn} disabled={page <= 1} onClick={() => onPage(page - 1)}><ChevronLeft className="h-4 w-4" aria-hidden />Previous</button>
        <span className="tabular-nums">Page {page} of {pages}</span>
        <button className={btn} disabled={page >= pages} onClick={() => onPage(page + 1)}>Next<ChevronRight className="h-4 w-4" aria-hidden /></button>
      </div>
    </nav>
  );
}
