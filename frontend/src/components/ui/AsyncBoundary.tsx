import type { ReactNode } from "react";
import type { AsyncState } from "../../hooks/useAsync";
import { ErrorState, LoadingBlock } from "./States";

/** Loading / error / content switch. Keeps showing existing data while a refresh is in flight. */
export function AsyncBoundary<T>({ state, rows = 4, label, children }: {
  state: AsyncState<T>; rows?: number; label?: string; children: (data: T) => ReactNode;
}) {
  if (state.error) return <ErrorState message={state.error} onRetry={state.reload} />;
  if (state.data == null) return <LoadingBlock rows={rows} label={label} />;
  return <>{children(state.data)}</>;
}
