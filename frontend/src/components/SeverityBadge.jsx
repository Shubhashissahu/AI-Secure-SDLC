const SEVERITY_STYLES = {
  critical: "bg-red-100 text-red-800 border-red-300",
  high: "bg-orange-100 text-orange-800 border-orange-300",
  medium: "bg-yellow-100 text-yellow-800 border-yellow-300",
  low: "bg-green-100 text-green-800 border-green-300",
  pass: "bg-green-100 text-green-800 border-green-300",
  fail: "bg-red-100 text-red-800 border-red-300",
  pending: "bg-yellow-100 text-yellow-800 border-yellow-300"
};

/**
 * Small colored badge for a Finding's severity level or scan gate result.
 * Reused across the findings list, finding detail page, and (later) PR
 * comment previews, so the color mapping lives in one place only.
 */
function SeverityBadge({ severity }) {
  const key = String(severity).toLowerCase();
  const styles = SEVERITY_STYLES[key] || "bg-slate-100 text-slate-800 border-slate-300";

  return (
    <span
      className={`inline-block px-3 py-1 rounded text-xs font-semibold uppercase border ${styles}`}
    >
      {severity}
    </span>
  );
}

export default SeverityBadge;