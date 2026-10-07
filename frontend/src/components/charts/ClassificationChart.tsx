import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { AXIS, tooltipStyle } from "./chartTheme";

export function ClassificationChart({ data }: { data: { name: string; count: number }[] }) {
  const rows = data.slice(0, 8);
  return (
    <div className="w-full" style={{ height: Math.max(160, rows.length * 28) }} role="img" aria-label="Alerts by threat classification">
      <ResponsiveContainer>
        <BarChart data={rows} layout="vertical" margin={{ top: 0, right: 12, left: 0, bottom: 0 }}>
          <XAxis type="number" hide />
          <YAxis type="category" dataKey="name" width={170} {...AXIS} tickFormatter={(v: string) => (v.length > 26 ? `${v.slice(0, 25)}…` : v)} />
          <Tooltip {...tooltipStyle} formatter={(v) => [v, "Alerts"]} />
          <Bar dataKey="count" fill="#4aa8ff" radius={[0, 3, 3, 0]} barSize={14} isAnimationActive={false} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
