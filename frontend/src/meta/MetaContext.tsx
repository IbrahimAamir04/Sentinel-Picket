import { createContext, useContext, type ReactNode } from "react";
import { useAsync } from "../hooks/useAsync";
import { api } from "../services";
import type { Meta } from "../types";

interface MetaValue { meta: Meta | null; error: string | null }
const Ctx = createContext<MetaValue>({ meta: null, error: null });

/** Server facts (demo or live, enabled features). The endpoint is public, so this loads before sign-in. */
export function MetaProvider({ children }: { children: ReactNode }) {
  const { data, error } = useAsync(() => api.meta(), []);
  return <Ctx.Provider value={{ meta: data, error }}>{children}</Ctx.Provider>;
}

export const useMeta = () => useContext(Ctx);
