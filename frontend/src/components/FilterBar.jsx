/**
 * Filter and search bar component for security findings.
 */
function FilterBar({ filters, onChange, onReset }) {
  return (
    <div className="card p-4 mb-6 flex flex-wrap items-center justify-between gap-4">
      <div className="flex flex-wrap items-center gap-3 flex-1">
        {/* Search Input */}
        <div className="relative min-w-[220px] flex-1">
          <span className="absolute left-3 top-2.5 text-slate-500 text-xs">🔍</span>
          <input
            type="text"
            placeholder="Search file, rule ID, description..."
            value={filters.search || ""}
            onChange={(e) => onChange({ ...filters, search: e.target.value })}
            className="input-field pl-8 text-xs"
          />
        </div>

        {/* Category Dropdown */}
        <select
          value={filters.category || ""}
          onChange={(e) => onChange({ ...filters, category: e.target.value })}
          className="input-field text-xs w-auto min-w-[150px] font-semibold text-indigo-300 bg-indigo-950/40 border-indigo-700/40"
        >
          <option value="">All Categories</option>
          <option value="SAST">🔬 SAST (Code Analysis)</option>
          <option value="AI_SECURITY">🤖 AI SECURITY (LLM & Prompts)</option>
          <option value="SCA">📦 SCA (Dependencies)</option>
          <option value="SECRETS">🔑 SECRETS (Credentials)</option>
          <option value="CONTAINER">🐳 CONTAINER (Docker)</option>
          <option value="IAC">☁️ IAC (Terraform/K8s)</option>
          <option value="CI_CD">⚙️ CI/CD (GitHub Actions)</option>
        </select>

        {/* Severity Dropdown */}
        <select
          value={filters.severity || ""}
          onChange={(e) => onChange({ ...filters, severity: e.target.value })}
          className="input-field text-xs w-auto min-w-[130px]"
        >
          <option value="">All Severities</option>
          <option value="critical">🔴 Critical</option>
          <option value="high">🟠 High</option>
          <option value="medium">🟡 Medium</option>
          <option value="low">🟢 Low</option>
        </select>

        {/* Status Dropdown */}
        <select
          value={filters.status || ""}
          onChange={(e) => onChange({ ...filters, status: e.target.value })}
          className="input-field text-xs w-auto min-w-[130px]"
        >
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="confirmed">Confirmed</option>
          <option value="likely">Likely</option>
          <option value="needs_review">Needs Review</option>
          <option value="false_positive">False Positive</option>
          <option value="remediated">Remediated</option>
          <option value="resolved">Resolved</option>
        </select>

        {/* Tool Dropdown */}
        <select
          value={filters.tool || ""}
          onChange={(e) => onChange({ ...filters, tool: e.target.value })}
          className="input-field text-xs w-auto min-w-[140px]"
        >
          <option value="">All Scanners</option>
          <option value="semgrep">Semgrep (SAST)</option>
          <option value="ai-security-scanner">AI Security (LLM)</option>
          <option value="gitleaks">Gitleaks (Secrets)</option>
          <option value="secret-scanner">Secret Scanner (Keys)</option>
          <option value="trivy">Trivy (SCA/IaC)</option>
          <option value="osv">OSV Live DB (SCA)</option>
          <option value="container-scanner">Container Scanner (Docker)</option>
          <option value="iac-scanner">IaC Scanner (TF/K8s)</option>
          <option value="cicd-scanner">CI/CD Scanner (Workflows)</option>
        </select>
      </div>

      {(filters.search || filters.category || filters.severity || filters.status || filters.tool) && (
        <button
          onClick={onReset}
          className="btn-ghost text-xs text-slate-400 hover:text-slate-200"
        >
          Reset Filters
        </button>
      )}
    </div>
  );
}

export default FilterBar;
