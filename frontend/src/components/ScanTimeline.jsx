import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from "recharts";

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;

  const data = payload[0].payload;
  const formattedDate = new Date(label).toLocaleString();

  return (
    <div className="card px-3 py-2 text-xs space-y-1">
      <div className="font-semibold text-slate-200">PR #{data.prNumber}</div>
      <div className="text-slate-400 text-[10px]">{formattedDate}</div>
      <div className="pt-1 border-t border-slate-700/60 grid grid-cols-2 gap-x-3 gap-y-0.5">
        <span className="text-red-400">Critical: {data.critical}</span>
        <span className="text-orange-400">High: {data.high}</span>
        <span className="text-amber-400">Medium: {data.medium}</span>
        <span className="text-emerald-400">Low: {data.low}</span>
      </div>
    </div>
  );
}

/**
 * AreaChart visualising security findings over recent scan iterations.
 */
function ScanTimeline({ data = [] }) {
  if (!data || data.length === 0) {
    return (
      <div className="flex items-center justify-center h-48 text-slate-500 text-sm">
        No scan history available
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
        <defs>
          <linearGradient id="criticalGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
            <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="highGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#f97316" stopOpacity={0.4} />
            <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="mediumGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#eab308" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#eab308" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(148, 163, 184, 0.08)" vertical={false} />
        <XAxis
          dataKey="date"
          tickFormatter={(val) => new Date(val).toLocaleDateString(undefined, { month: "short", day: "numeric" })}
          stroke="#64748b"
          fontSize={11}
          tickLine={false}
        />
        <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
        <Tooltip content={<CustomTooltip />} />
        <Area
          type="monotone"
          dataKey="critical"
          stackId="1"
          stroke="#ef4444"
          fill="url(#criticalGrad)"
          strokeWidth={2}
        />
        <Area
          type="monotone"
          dataKey="high"
          stackId="1"
          stroke="#f97316"
          fill="url(#highGrad)"
          strokeWidth={2}
        />
        <Area
          type="monotone"
          dataKey="medium"
          stackId="1"
          stroke="#eab308"
          fill="url(#mediumGrad)"
          strokeWidth={2}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export default ScanTimeline;
