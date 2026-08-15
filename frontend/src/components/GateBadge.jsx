
/**
 * Renders a visual status badge for security gate results (pass / fail / pending).
 */
function GateBadge({ result }) {
  const normalized = (result || "pending").toLowerCase();

  let styles = "bg-slate-700/50 text-slate-300 border-slate-600";
  let label = normalized.toUpperCase();

  if (normalized === "pass" || normalized === "passed") {
    styles = "bg-emerald-500/15 text-emerald-400 border-emerald-500/30";
    label = "PASS";
  } else if (normalized === "fail" || normalized === "failed") {
    styles = "bg-rose-500/15 text-rose-400 border-rose-500/30";
    label = "FAIL";
  } else if (normalized === "pending") {
    styles = "bg-amber-500/15 text-amber-400 border-amber-500/30";
    label = "PENDING";
  }

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border ${styles}`}
    >
      {label}
    </span>
  );
}

export default GateBadge;
