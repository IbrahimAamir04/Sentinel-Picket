import { Link } from "react-router-dom";
import { useDocumentTitle } from "../hooks/useDocumentTitle";

export default function NotFound() {
  useDocumentTitle("Page not found");
  return (
    <div className="py-20 text-center">
      <h1 className="text-xl font-semibold">Page not found</h1>
      <p className="mt-1 text-sm text-muted">Sentinel has three pages: dashboard, alerts and payloads.</p>
      <Link to="/" className="mt-4 inline-flex h-9 items-center rounded-md border border-line-strong px-3 text-sm hover:bg-raised">Go to dashboard</Link>
    </div>
  );
}
