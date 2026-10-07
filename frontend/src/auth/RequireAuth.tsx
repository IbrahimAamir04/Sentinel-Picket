import { Navigate, Outlet, useLocation } from "react-router-dom";
import { LoadingBlock, ErrorState } from "../components/ui/States";
import { useAuth } from "./AuthContext";

export function RequireAuth() {
  const { status, error, retry } = useAuth();
  const loc = useLocation();
  if (status === "loading") return <LoadingBlock rows={4} label="Checking your session" />;
  if (status === "error") return <ErrorState message={error ?? "Couldn't check your session."} onRetry={retry} />;
  if (status === "anonymous") return <Navigate to="/login" replace state={{ from: loc.pathname + loc.search }} />;
  return <Outlet />;
}
