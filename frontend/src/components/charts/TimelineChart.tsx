import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { TimelinePoint, TimelineRange } from "../../types";
import { SEVERITIES, SEVERITY_COLOR, label } from "../../utils/constants";
import { fmtDay, fmtTime } from "../../utils/format";
import { AXIS, ChartLegend, GRID, tooltipStyle } from "./chartTheme";

export function TimelineChart({ data, range }: { data: TimelinePoint[]; range: TimelineRange }) {
  const fmt = (iso: string) => (range === "24h" ? fmtTime(iso) : fmtDay(iso));
  return (
    <div className="space-y-2">
      <div className="h-56 w-full" role="img" aria-label={`Alert counts per ${range === "24h" ? "hour" : "day"} by severity`}>
        <ResponsiveContainer>
          <BarChart data={data} margin={{ top: 4, right: 4, left: -18, bottom: 0 }}>
            <CartesianGrid stroke={GRID} vertical={false} />
            <XAxis dataKey="bucket" tickFormatter={fmt} {...AXIS} minTickGap={24} />
            <YAxis allowDecimals={false} {...AXIS} />
            <Tooltip {...tooltipStyle} labelFormatter={(v) => fmt(String(v))} />
            {[...SEVERITIES].reverse().map((s) => (
              <Bar key={s} dataKey={s} name={label(s)} stackId="a" fill={SEVERITY_COLOR[s]} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
      <ChartLegend items={SEVERITIES.map((s) => ({ name: label(s), color: SEVERITY_COLOR[s] }))} />
    </div>
  );
}
