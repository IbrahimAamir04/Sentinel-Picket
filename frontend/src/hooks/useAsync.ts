import { useCallback, useEffect, useRef, useState } from "react";

export interface AsyncState<T> {
  data: T | null;
  loading: boolean; // true on first load and on every reload
  error: string | null;
  updatedAt: number | null;
  reload: () => void;
}

/** Runs an async loader whenever deps change. Ignores stale responses. Keeps previous data visible while reloading. */
export function useAsync<T>(loader: () => Promise<T>, deps: unknown[]): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);
  const [tick, setTick] = useState(0);
  const seq = useRef(0);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;

  useEffect(() => {
    const id = ++seq.current;
    setLoading(true);
    setError(null);
    loaderRef.current()
      .then((d) => { if (id === seq.current) { setData(d); setUpdatedAt(Date.now()); } })
      .catch((e: unknown) => { if (id === seq.current) setError(e instanceof Error ? e.message : "Request failed."); })
      .finally(() => { if (id === seq.current) setLoading(false); });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { data, loading, error, updatedAt, reload };
}
