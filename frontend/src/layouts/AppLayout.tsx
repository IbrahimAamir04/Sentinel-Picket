import { Menu } from "lucide-react";
import { useState } from "react";
import { Outlet } from "react-router-dom";
import { DemoBanner } from "../components/layout/DemoBanner";
import { Sidebar } from "../components/layout/Sidebar";

export function AppLayout() {
  const [navOpen, setNavOpen] = useState(false);
  return (
    <div className="flex h-full">
      <Sidebar open={navOpen} onClose={() => setNavOpen(false)} />
      <div className="flex min-w-0 flex-1 flex-col">
        <DemoBanner />
        <header className="flex h-12 items-center gap-2 border-b border-line px-3 lg:hidden">
          <button onClick={() => setNavOpen(true)} aria-label="Open navigation" aria-controls="primary-nav" aria-expanded={navOpen}
            className="rounded p-1.5 text-muted hover:bg-raised hover:text-fg"><Menu className="h-5 w-5" /></button>
          <span className="font-semibold">Sentinel</span>
        </header>
        <main className="flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-[96rem] space-y-4 p-3 sm:p-5"><Outlet /></div>
        </main>
      </div>
    </div>
  );
}
