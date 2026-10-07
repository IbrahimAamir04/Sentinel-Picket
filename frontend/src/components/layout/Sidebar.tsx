import { Bell, FileSearch, LayoutDashboard, LogOut, ShieldCheck, X } from "lucide-react";
import { NavLink } from "react-router-dom";
import { useAuth } from "../../auth/AuthContext";
import { label } from "../../utils/constants";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/alerts", label: "Snort alerts", icon: Bell, end: false },
  { to: "/payloads", label: "Payload intelligence", icon: FileSearch, end: false },
];

export function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { user, canSignOut, logout } = useAuth();
  return (
    <>
      {open && <div className="fixed inset-0 z-30 bg-black/60 lg:hidden" onClick={onClose} aria-hidden />}
      <aside id="primary-nav" aria-label="Primary"
        className={`fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-line bg-surface transition-transform lg:static lg:translate-x-0 ${open ? "translate-x-0" : "-translate-x-full"}`}>
        <div className="flex h-14 items-center justify-between border-b border-line px-4">
          <div className="flex items-center gap-2 font-semibold text-fg">
            <ShieldCheck className="h-5 w-5 text-accent" aria-hidden /> Sentinel
          </div>
          <button onClick={onClose} aria-label="Close navigation" className="rounded p-1 text-muted hover:bg-raised lg:hidden"><X className="h-5 w-5" /></button>
        </div>
        <nav className="flex-1 space-y-1 p-3">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink key={to} to={to} end={end} onClick={onClose}
              className={({ isActive }) => `flex items-center gap-2.5 rounded-md px-3 py-2 text-sm ${isActive ? "bg-raised text-fg" : "text-muted hover:bg-raised/60 hover:text-fg"}`}>
              <Icon className="h-4 w-4" aria-hidden /> {label}
            </NavLink>
          ))}
        </nav>
        <div className="flex items-center justify-between gap-2 border-t border-line p-3">
          <div className="min-w-0 text-sm">
            <div className="truncate text-fg">{user?.username}</div>
            <div className="text-xs text-muted">{user ? label(user.role) : ""}</div>
          </div>
          {canSignOut && (
            <button onClick={() => void logout()} className="inline-flex h-8 items-center gap-1.5 rounded-md border border-line-strong px-2.5 text-xs text-fg hover:bg-raised">
              <LogOut className="h-3.5 w-3.5" aria-hidden /> Sign out
            </button>
          )}
        </div>
      </aside>
    </>
  );
}
