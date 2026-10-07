import { useEffect, useState } from "react";
import { useDebounced } from "./useDebounced";

/** Local text state for a search box that writes to the URL after the user pauses typing. */
export function useSearchInput(urlValue: string, commit: (v: string) => void) {
  const [text, setText] = useState(urlValue);
  const debounced = useDebounced(text, 300);

  useEffect(() => { setText(urlValue); }, [urlValue]);
  useEffect(() => { if (debounced !== urlValue) commit(debounced); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [debounced]);

  return [text, setText] as const;
}
