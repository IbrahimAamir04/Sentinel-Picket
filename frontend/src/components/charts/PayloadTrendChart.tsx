import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { PayloadTrendPoint } from "../../types";
import { STATUS_COLOR, label } from "../../utils/constants";
import { fmtDay } from "../../utils/format";
import { AXIS, ChartLegend, GRID, tooltipStyle } from "./chartTheme";

const KEYS = ["MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"] as const;

export function PayloadTrendChart({ data }: { data: PayloadTrendPoint[] }) {
  return (
    <div className="space-y-2">
      <div className="h-48 w-full" role="img" aria-label="New payloads per day by status, last 14 days">
        <ResponsiveContainer>
          <BarChart data={data} margin={{ top: 4, right: 4, left: -18, bottom: 0 }}>
            <CartesianGrid stroke={GRID} vertical={false} />
            <XAxis dataKey="day" tickFormatter={fmtDay} {...AXIS} minTickGap={20} />
            <YAxis allowDecimals={false} {...AXIS} />
            <Tooltip {...tooltipStyle} labelFormatter={(v) => fmtDay(String(v))} />
            {[...KEYS].reverse().map((k) => <Bar key={k} dataKey={k} name={label(k)} stackId="a" fill={STATUS_COLOR[k]} isAnimationActive={false} />)}
          </BarChart>
        </ResponsiveContainer>
      </div>
      <ChartLegend items={KEYS.map((k) => ({ name: label(k), color: STATUS_COLOR[k] }))} />
    </div>
  );
}
