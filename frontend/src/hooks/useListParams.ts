import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";

/**
 * Keeps list state (search, filters, sort, page) in the URL so views can be shared, bookmarked
 * and restored with the back button. Changing any filter resets to page 1.
 */
export function useListParams(defaultOrdering: string) {
  const [sp, setSp] = useSearchParams();

  const params = useMemo(() => {
    const o: Record<string, string> = {};
    sp.forEach((v, k) => { o[k] = v; });
    return o;
  }, [sp]);

  const ordering = params.ordering || defaultOrdering;
  const page = Math.max(1, Number(params.page) || 1);

  const patch = useCallback((changes: Record<string, string | number | null | undefined>, keepPage = false) => {
    setSp((prev) => {
      const next = new URLSearchParams(prev);
      for (const [k, v] of Object.entries(changes)) {
        if (v === null || v === undefined || v === "") next.delete(k);
        else next.set(k, String(v));
      }
      if (!keepPage && !("page" in changes)) next.delete("page");
      return next;
    }, { replace: true });
  }, [setSp]);

  /** Click cycles direction on the active column; a new column starts descending only when descFirst is set. */
  const toggleSort = useCallback((field: string, descFirst = false) => {
    if (ordering === field) patch({ ordering: `-${field}` });
    else if (ordering === `-${field}`) patch({ ordering: field });
    else patch({ ordering: descFirst ? `-${field}` : field });
  }, [ordering, patch]);

  return { params, ordering, page, patch, toggleSort };
}
