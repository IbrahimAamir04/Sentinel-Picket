import { ShieldCheck } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { DemoBanner } from "../components/layout/DemoBanner";
import { Notice } from "../components/ui/ConfirmDialog";
import { useDocumentTitle } from "../hooks/useDocumentTitle";

const input = "h-10 w-full rounded-md border border-line-strong bg-bg px-3 text-sm text-fg placeholder:text-faint";

export default function Login() {
  useDocumentTitle("Sign in");
  const { status, login } = useAuth();
  const nav = useNavigate();
  const from = (useLocation().state as { from?: string } | null)?.from ?? "/";
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (status === "authenticated") return <Navigate to={from} replace />;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      await login(username.trim(), password);
      nav(from, { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign in failed.");
      setPassword("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-full flex-col">
      <DemoBanner />
      <main className="flex flex-1 items-center justify-center p-4">
        <form onSubmit={submit} className="w-full max-w-sm space-y-4 rounded-lg border border-line bg-surface p-6" aria-label="Sign in">
          <div className="flex items-center gap-2 text-lg font-semibold text-fg">
            <ShieldCheck className="h-6 w-6 text-accent" aria-hidden /> Sentinel
          </div>
          <p className="text-sm text-muted">Sign in to view alerts, payloads and sensor health.</p>
          {error && <Notice tone="error">{error}</Notice>}
          <label className="block space-y-1.5 text-sm">
            <span className="block text-muted">Username</span>
            <input className={input} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus required maxLength={150} />
          </label>
          <label className="block space-y-1.5 text-sm">
            <span className="block text-muted">Password</span>
            <input className={input} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required maxLength={256} />
          </label>
          <button type="submit" disabled={busy || !username || !password}
            className="h-10 w-full rounded-md bg-accent text-sm font-medium text-black hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50">
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </main>
    </div>
  );
}
