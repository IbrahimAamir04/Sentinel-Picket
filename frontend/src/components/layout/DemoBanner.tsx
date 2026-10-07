import { FlaskConical } from "lucide-react";
import { useMeta } from "../../meta/MetaContext";

/** Shown only when the server reports demo mode. Live telemetry is never labelled as demo, and demo data never goes unlabelled. */
export function DemoBanner() {
  const { meta } = useMeta();
  if (meta?.mode !== "demo") return null;
  return (
    <div role="note" className="flex items-center gap-2 border-b border-med/30 bg-med/10 px-4 py-1.5 text-xs text-med">
      <FlaskConical className="h-3.5 w-3.5 shrink-0" aria-hidden />
      <span><strong className="font-semibold">DEMO MODE / MOCK DATA</strong> – every alert, payload and sensor shown here is synthetic. Nothing is real telemetry.</span>
    </div>
  );
}
