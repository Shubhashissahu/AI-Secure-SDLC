import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from "recharts";

const SEVERITY_COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

const SEVERITY_LABELS = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

function CustomTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const { name, value } = payload[0];
  return (
    <div className="card px-3 py-2 text-xs">
      <span className="font-semibold capitalize">{SEVERITY_LABELS[name] || name}</span>
      <span className="text-slate-400 ml-2">{value} findings</span>
    </div>
  );
}

function CustomLegend({ payload }) {
  return (
    <div className="flex flex-wrap justify-center gap-3 mt-3">
      {payload.map((entry, idx) => (
        <div key={idx} className="flex items-center gap-1.5 text-xs text-slate-300">
          <span
            className="w-2.5 h-2.5 rounded-full"
            style={{ backgroundColor: entry.color }}
          />
          <span className="capitalize">{SEVERITY_LABELS[entry.value] || entry.value}</span>
        </div>
      ))}
    </div>
  );
}

/**
 * Donut chart showing the severity breakdown of findings.
 */
function SeverityDistributionChart({ data = [] }) {
  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-48 text-slate-500 text-sm">
        No findings data available
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie
          data={data}
          cx="50%"
          cy="45%"
          innerRadius={50}
          outerRadius={75}
          paddingAngle={3}
          dataKey="value"
          nameKey="name"
          strokeWidth={0}
        >
          {data.map((entry, idx) => (
            <Cell
              key={idx}
              fill={SEVERITY_COLORS[entry.name] || entry.fill || "#6b7280"}
            />
          ))}
        </Pie>
        <Tooltip content={<CustomTooltip />} />
        <Legend content={<CustomLegend />} />
      </PieChart>
    </ResponsiveContainer>
  );
}

export default SeverityDistributionChart;
