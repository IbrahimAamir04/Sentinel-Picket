import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import type { ProtocolSlice } from "../../types";
import { ChartLegend, tooltipStyle } from "./chartTheme";

const COLORS = ["#4aa8ff", "#34c38f", "#e3b341", "#a06bd6", "#6b7788"];

export function ProtocolChart({ data }: { data: ProtocolSlice[] }) {
  const total = data.reduce((s, d) => s + d.count, 0);
  return (
    <div className="space-y-2">
      <div className="h-44 w-full" role="img" aria-label="Alert share by protocol">
        <ResponsiveContainer>
          <PieChart>
            <Pie data={data} dataKey="count" nameKey="protocol" innerRadius="58%" outerRadius="85%" stroke="#11161d" strokeWidth={2} isAnimationActive={false}>
              {data.map((d, i) => <Cell key={d.protocol} fill={COLORS[i % COLORS.length]} />)}
            </Pie>
            <Tooltip {...tooltipStyle} formatter={(v) => [`${v} (${total ? (((v as number) / total) * 100).toFixed(1) : 0}%)`, "Alerts"]} />
          </PieChart>
        </ResponsiveContainer>
      </div>
      <ChartLegend items={data.map((d, i) => ({ name: `${d.protocol} ${total ? Math.round((d.count / total) * 100) : 0}%`, color: COLORS[i % COLORS.length] }))} />
    </div>
  );
}
