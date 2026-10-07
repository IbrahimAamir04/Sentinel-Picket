export const AXIS = { stroke: "#5d6a7b", fontSize: 11, tickLine: false, axisLine: { stroke: "#232b36" } } as const;
export const GRID = "#1c2430";

export const tooltipStyle = {
  contentStyle: { background: "#161c25", border: "1px solid #2f3947", borderRadius: 6, fontSize: 12, color: "#d6dde6" },
  labelStyle: { color: "#8693a4" },
  itemStyle: { color: "#d6dde6" },
  cursor: { fill: "rgba(74,168,255,0.06)" },
};

export function ChartLegend({ items }: { items: { name: string; color: string }[] }) {
  return (
    <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted">
      {items.map((i) => (
        <li key={i.name} className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-sm" style={{ background: i.color }} aria-hidden />{i.name}
        </li>
      ))}
    </ul>
  );
}
