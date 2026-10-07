import type { ListQuery, Paginated } from "../types";

export const DEFAULT_PAGE_SIZE = 20;

type Getter<T> = (row: T) => string | number | null | undefined;

/** Generic search + sort + paginate helper used by the demo source. Filtering is done by the caller. */
export function searchSortPaginate<T>(
  rows: T[],
  q: ListQuery,
  searchText: (row: T) => string,
  sortFields: Record<string, Getter<T>>,
  defaultOrdering: string,
): Paginated<T> {
  let out = rows;
  const term = q.search?.toString().trim().toLowerCase();
  if (term) out = out.filter((r) => searchText(r).toLowerCase().includes(term));

  const ordering = q.ordering?.toString() || defaultOrdering;
  const desc = ordering.startsWith("-");
  const getter = sortFields[desc ? ordering.slice(1) : ordering] ?? sortFields[defaultOrdering.replace(/^-/, "")];
  if (getter) {
    out = [...out].sort((a, b) => {
      const av = getter(a) ?? "";
      const bv = getter(b) ?? "";
      const cmp = typeof av === "number" && typeof bv === "number" ? av - bv : String(av).localeCompare(String(bv));
      return desc ? -cmp : cmp;
    });
  }

  const page_size = Math.min(Math.max(Number(q.page_size) || DEFAULT_PAGE_SIZE, 1), 100);
  const pages = Math.max(1, Math.ceil(out.length / page_size));
  const page = Math.min(Math.max(Number(q.page) || 1, 1), pages);
  return { count: out.length, page, page_size, results: out.slice((page - 1) * page_size, page * page_size) };
}
