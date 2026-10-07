import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { authApi, dataMode } from "../services";
import { UNAUTHORIZED_EVENT } from "../services/http";
import type { AuthUser } from "../types";

type Status = "loading" | "anonymous" | "authenticated" | "error";

interface AuthValue {
  status: Status;
  user: AuthUser | null;
  error: string | null;
  canSignOut: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  retry: () => void;
}

const Ctx = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>("loading");
  const [user, setUser] = useState<AuthUser | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let live = true;
    setStatus("loading");
    authApi.me()
      .then((u) => { if (!live) return; setUser(u); setStatus(u ? "authenticated" : "anonymous"); })
      .catch((e: unknown) => { if (!live) return; setError(e instanceof Error ? e.message : "Couldn't check your session."); setStatus("error"); });
    return () => { live = false; };
  }, [tick]);

  // Any 401 from the API (expired session, logged out elsewhere) sends the user back to sign in.
  useEffect(() => {
    const onUnauthorized = () => { setUser(null); setStatus("anonymous"); };
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    const u = await authApi.login(username, password);
    setUser(u); setStatus("authenticated"); setError(null);
  }, []);

  const logout = useCallback(async () => {
    try { await authApi.logout(); } finally { setUser(null); setStatus("anonymous"); }
  }, []);

  const value = useMemo<AuthValue>(
    () => ({ status, user, error, canSignOut: dataMode !== "demo", login, logout, retry: () => setTick((t) => t + 1) }),
    [status, user, error, login, logout],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthValue {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth must be used inside AuthProvider");
  return v;
}
