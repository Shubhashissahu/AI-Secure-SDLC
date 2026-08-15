import { useEffect, useState, useMemo, useCallback } from "react";
import { Link, useSearchParams } from "react-router-dom";
import api, { getCached } from "../services/api";
import SeverityBadge from "../components/SeverityBadge";
import FilterBar from "../components/FilterBar";

function CustomRemoteScanModal({ onClose, onScanned }) {
  const [githubUrl, setGithubUrl] = useState("https://github.com/Shubhashissahu/Testing");
  const [commitSha, setCommitSha] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(e) {
    e.preventDefault();
    if (submitting) return;
    setError("");
    setSubmitting(true);
    try {
      await api.post("/api/scans/custom-remote", {
        githubUrl: githubUrl.trim(),
        commitSha: commitSha.trim() || undefined
      });
      onScanned();
      onClose();
    } catch (err) {
      setError(err.response?.data?.message || err.message || "Failed to scan remote repository.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 w-full max-w-lg shadow-2xl animate-fade-in-up">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-bold flex items-center gap-2">
            <span>🌐</span> Scan Any Remote GitHub Repository
          </h2>
          <button onClick={onClose} disabled={submitting} className="text-slate-400 hover:text-white text-xl">
            ✕
          </button>
        </div>

        <p className="text-xs text-slate-400 mb-4">
          Enter any public or accessible GitHub repository URL below. The system will clone the repository, run static scanners, verify source code presence, analyze code with AI, and report verified findings.
        </p>

        {error && (
          <div className="bg-red-950/40 border border-red-800/40 text-red-300 text-xs rounded-lg px-3 py-2.5 mb-4">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              GitHub Repository URL <span className="text-red-400">*</span>
            </label>
            <input
              required
              disabled={submitting}
              type="url"
              placeholder="e.g. https://github.com/owner/repo"
              value={githubUrl}
              onChange={(e) => setGithubUrl(e.target.value)}
              className="input-field text-xs font-mono"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              Commit SHA / Branch <span className="text-slate-500 font-normal">(Optional - defaults to latest HEAD)</span>
            </label>
            <input
              disabled={submitting}
              type="text"
              placeholder="e.g. main, or 41085fdb3527aa94640edc11bd60f41a5118ba16"
              value={commitSha}
              onChange={(e) => setCommitSha(e.target.value)}
              className="input-field text-xs font-mono"
            />
          </div>

          <div className="flex items-center gap-3 pt-2">
            <button
              type="submit"
              disabled={submitting}
              className="btn-primary flex-1 text-xs py-2.5 flex items-center justify-center gap-2"
            >
              {submitting ? (
                <>
                  <span className="animate-spin">⏳</span>
                  <span>Cloning, Verifying & Scanning Remote Repo...</span>
                </>
              ) : (
                <>
                  <span>🚀</span>
                  <span>Start Production Scan</span>
                </>
              )}
            </button>
            <button
              type="button"
              onClick={onClose}
              disabled={submitting}
              className="btn-secondary text-xs py-2.5"
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function Findings() {
  const [searchParams] = useSearchParams();
  const scanId = searchParams.get("scanId");
  const urlCategory = searchParams.get("category");

  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showModal, setShowModal] = useState(false);
  const [ollamaStatus, setOllamaStatus] = useState(null);

  const [filters, setFilters] = useState({
    search: "",
    category: urlCategory || "",
    severity: "",
    status: "",
    tool: ""
  });

  useEffect(() => {
    if (urlCategory !== null && urlCategory !== undefined) {
      setFilters((prev) => ({ ...prev, category: urlCategory }));
    }
  }, [urlCategory]);

  const fetchFindings = useCallback((signal) => {
    setLoading(true);
    const params = {};
    if (scanId) params.scanId = scanId;
    if (filters.category) params.category = filters.category;
    if (filters.severity) params.severity = filters.severity;
    if (filters.tool) params.tool = filters.tool;

    return api
      .get("/api/findings", { params, signal })
      .then((res) => {
        setFindings(res.data.data || []);
        setError("");
      })
      .catch((err) => {
        if (err.name === "CanceledError" || err.code === "ERR_CANCELED") return;
        setError("Failed to load findings.");
      })
      .finally(() => setLoading(false));
  }, [scanId, filters.category, filters.severity, filters.tool]);

  const fetchOllamaStatus = useCallback((signal) => {
    return getCached("/api/findings/ollama-status", { signal }, 15000)
      .then((res) => setOllamaStatus(res.data.data))
      .catch((err) => {
        if (err.name === "CanceledError" || err.code === "ERR_CANCELED") return;
        setOllamaStatus({ isConnected: false, activeModel: "offline" });
      });
  }, []);

  // Fetch Ollama infrastructure status once on mount
  useEffect(() => {
    const controller = new AbortController();
    fetchOllamaStatus(controller.signal);
    return () => controller.abort();
  }, [fetchOllamaStatus]);

  // Fetch findings on scanId or filter change
  useEffect(() => {
    const controller = new AbortController();
    fetchFindings(controller.signal);
    return () => controller.abort();
  }, [fetchFindings]);

  // Group findings by unique key: repository + file + line + rule to prevent duplicate rows
  const groupedFindings = useMemo(() => {
    const map = new Map();
    for (const f of findings) {
      const groupKey = `${f.repositoryId || ""}:${f.file}:${f.line}:${f.ruleId}`.toLowerCase();
      if (!map.has(groupKey)) {
        map.set(groupKey, {
          ...f,
          displayOccurrences: f.occurrences || 1
        });
      } else {
        const existing = map.get(groupKey);
        existing.displayOccurrences = (existing.displayOccurrences || 1) + (f.occurrences || 1);
        if (new Date(f.updatedAt || f.createdAt) > new Date(existing.updatedAt || existing.createdAt)) {
          map.set(groupKey, { ...f, displayOccurrences: existing.displayOccurrences });
        }
      }
    }
    return Array.from(map.values());
  }, [findings]);

  const categoryCounts = useMemo(() => {
    const counts = { ALL: 0, SAST: 0, AI_SECURITY: 0, SCA: 0, SECRETS: 0, CONTAINER: 0, IAC: 0, CI_CD: 0 };
    for (const f of groupedFindings) {
      counts.ALL++;
      const cat = (
        f.category || (
          f.tool === "ai-security-scanner" ? "AI_SECURITY" :
          f.tool === "gitleaks" || f.tool === "secret-scanner" ? "SECRETS" :
          f.tool === "container-scanner" ? "CONTAINER" :
          f.tool === "iac-scanner" ? "IAC" :
          f.tool === "cicd-scanner" ? "CI_CD" :
          f.tool === "trivy" || f.tool === "osv" ? "SCA" : "SAST"
        )
      ).toUpperCase();
      if (counts[cat] !== undefined) counts[cat]++;
      else counts.SAST++;
    }
    return counts;
  }, [groupedFindings]);

  const filteredFindings = useMemo(() => {
    return groupedFindings.filter((f) => {
      const fCat = (
        f.category || (
          f.tool === "ai-security-scanner" ? "AI_SECURITY" :
          f.tool === "gitleaks" || f.tool === "secret-scanner" ? "SECRETS" :
          f.tool === "container-scanner" ? "CONTAINER" :
          f.tool === "iac-scanner" ? "IAC" :
          f.tool === "cicd-scanner" ? "CI_CD" :
          f.tool === "trivy" || f.tool === "osv" ? "SCA" : "SAST"
        )
      ).toUpperCase();
      if (filters.category && fCat !== filters.category.toUpperCase()) return false;
      if (filters.severity && f.severity?.toLowerCase() !== filters.severity.toLowerCase()) return false;
      if (filters.status && f.status?.toUpperCase() !== filters.status.toUpperCase()) return false;
      if (filters.tool && f.tool?.toLowerCase() !== filters.tool.toLowerCase()) return false;

      if (filters.search) {
        const query = filters.search.toLowerCase();
        const matchesFile = f.file?.toLowerCase().includes(query);
        const matchesRule = f.ruleId?.toLowerCase().includes(query);
        const matchesDesc = f.description?.toLowerCase().includes(query);
        const matchesPkg = f.package?.toLowerCase().includes(query);
        const matchesCve = f.cve?.toLowerCase().includes(query);
        const matchesResource = f.resourceName?.toLowerCase().includes(query) || f.resourceType?.toLowerCase().includes(query);
        const matchesWorkflow = f.workflowName?.toLowerCase().includes(query) || f.actionName?.toLowerCase().includes(query);
        if (!matchesFile && !matchesRule && !matchesDesc && !matchesPkg && !matchesCve && !matchesResource && !matchesWorkflow) return false;
      }

      return true;
    });
  }, [groupedFindings, filters]);

  return (
    <div className="space-y-6">
      {showModal && (
        <CustomRemoteScanModal
          onClose={() => setShowModal(false)}
          onScanned={() => {
            fetchFindings();
            fetchOllamaStatus();
          }}
        />
      )}

      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <span>🛡️</span> Security Vulnerabilities & Findings
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time multi-scanner findings (SAST, AI Security, SCA, Secrets, Container, IaC & CI/CD) triaged with AI.
          </p>
        </div>

        <button
          onClick={() => setShowModal(true)}
          className="btn-primary text-xs flex items-center gap-2 self-start sm:self-auto"
        >
          <span>🌐</span>
          <span>Scan Remote GitHub Repo</span>
        </button>
      </div>

      <div className="flex items-center gap-2 border-b border-slate-800 pb-3 overflow-x-auto">
        <button
          onClick={() => setFilters({ ...filters, category: "" })}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all shrink-0 ${
            !filters.category
              ? "bg-slate-700 text-white shadow-md"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
          }`}
        >
          <span>All Findings</span>
          <span className="bg-slate-900/80 px-1.5 py-0.5 rounded-full text-[10px] text-slate-300">
            {categoryCounts.ALL}
          </span>
        </button>

        <button
          onClick={() => setFilters({ ...filters, category: "SAST" })}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all shrink-0 ${
            filters.category === "SAST"
              ? "bg-indigo-600 text-white shadow-md shadow-indigo-600/30"
              : "text-indigo-400 hover:bg-indigo-950/40"
          }`}
        >
          <span>🔬 SAST</span>
          <span className="bg-indigo-950 border border-indigo-700/50 px-1.5 py-0.5 rounded-full text-[10px] text-indigo-300">
            {categoryCounts.SAST}
          </span>
        </button>

        <button
          onClick={() => setFilters({ ...filters, category: "AI_SECURITY" })}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all shrink-0 ${
            filters.category === "AI_SECURITY"
              ? "bg-purple-600 text-white shadow-md shadow-purple-600/30"
              : "text-purple-400 hover:bg-purple-950/40"
          }`}
        >
          <span>🤖 AI Security</span>
          <span className="bg-purple-950 border border-purple-700/50 px-1.5 py-0.5 rounded-full text-[10px] text-purple-300">
            {categoryCounts.AI_SECURITY}
          </span>
        </button>

        <button
          onClick={() => setFilters({ ...filters, category: "SCA" })}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all shrink-0 ${
            filters.category === "SCA"
              ? "bg-cyan-600 text-white shadow-md shadow-cyan-600/30"
              : "text-cyan-400 hover:bg-cyan-950/40"
          }`}
        >
          <span>📦 SCA</span>
          <span className="bg-cyan-950 border border-cyan-700/50 px-1.5 py-0.5 rounded-full text-[10px] text-cyan-300">
            {categoryCounts.SCA}
          </span>
        </button>

        <button
          onClick={() => setFilters({ ...filters, category: "SECRETS" })}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all shrink-0 ${
            filters.category === "SECRETS"
              ? "bg-rose-600 text-white shadow-md shadow-rose-600/30"
              : "text-rose-400 hover:bg-rose-950/40"
          }`}
        >
          <span>🔑 SECRETS</span>
          <span className="bg-rose-950 border border-rose-700/50 px-1.5 py-0.5 rounded-full text-[10px] text-rose-300">
            {categoryCounts.SECRETS}
          </span>
        </button>

        <button
          onClick={() => setFilters({ ...filters, category: "CONTAINER" })}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all shrink-0 ${
            filters.category === "CONTAINER"
              ? "bg-sky-600 text-white shadow-md shadow-sky-600/30"
              : "text-sky-400 hover:bg-sky-950/40"
          }`}
        >
          <span>🐳 CONTAINER</span>
          <span className="bg-sky-950 border border-sky-700/50 px-1.5 py-0.5 rounded-full text-[10px] text-sky-300">
            {categoryCounts.CONTAINER}
          </span>
        </button>

        <button
          onClick={() => setFilters({ ...filters, category: "IAC" })}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all shrink-0 ${
            filters.category === "IAC"
              ? "bg-amber-600 text-white shadow-md shadow-amber-600/30"
              : "text-amber-400 hover:bg-amber-950/40"
          }`}
        >
          <span>☁️ IAC</span>
          <span className="bg-amber-950 border border-amber-700/50 px-1.5 py-0.5 rounded-full text-[10px] text-amber-300">
            {categoryCounts.IAC}
          </span>
        </button>

        <button
          onClick={() => setFilters({ ...filters, category: "CI_CD" })}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all shrink-0 ${
            filters.category === "CI_CD"
              ? "bg-emerald-600 text-white shadow-md shadow-emerald-600/30"
              : "text-emerald-400 hover:bg-emerald-950/40"
          }`}
        >
          <span>⚙️ CI/CD</span>
          <span className="bg-emerald-950 border border-emerald-700/50 px-1.5 py-0.5 rounded-full text-[10px] text-emerald-300">
            {categoryCounts.CI_CD}
          </span>
        </button>
      </div>

      <FilterBar
        filters={filters}
        onChange={setFilters}
        onReset={() => setFilters({ search: "", category: "", severity: "", status: "", tool: "" })}
      />

      {error && (
        <div className="bg-red-950/40 border border-red-800/40 rounded-xl p-4 text-xs text-red-300">
          {error}
        </div>
      )}

      {loading ? (
        <div className="space-y-3 animate-pulse">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="card p-4 h-20 bg-slate-800/40" />
          ))}
        </div>
      ) : filteredFindings.length === 0 ? (
        <div className="card p-12 text-center">
          <div className="text-3xl mb-2">🎉</div>
          <p className="text-sm font-medium text-slate-300">No vulnerabilities found matching criteria.</p>
          <p className="text-xs text-slate-500 mt-1">All clean! Try changing your filters or trigger a new scan.</p>
        </div>
      ) : (
        <div className="space-y-2.5">
          {filteredFindings.map((f) => {
            const rawStatus = (f.status || "OPEN").toUpperCase();
            const riskScore = f.risk?.score || 0;
            const category = (
              f.category || (
                f.tool === "gitleaks" || f.tool === "secret-scanner" ? "SECRETS" :
                f.tool === "container-scanner" ? "CONTAINER" :
                f.tool === "iac-scanner" ? "IAC" :
                f.tool === "cicd-scanner" ? "CI_CD" :
                f.tool === "trivy" || f.tool === "osv" ? "SCA" : "SAST"
              )
            ).toUpperCase();

            return (
              <Link
                key={f._id || `${f.file}-${f.line}-${f.ruleId}`}
                to={`/findings/${f._id}`}
                className="card p-4 hover:border-slate-700 transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-4 block group"
              >
                <div className="flex items-start gap-3 min-w-0">
                  <div className="mt-0.5 shrink-0">
                    <SeverityBadge severity={f.severity} />
                  </div>

                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span
                        className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded border uppercase ${
                          category === "SCA"
                            ? "bg-cyan-950/70 text-cyan-300 border-cyan-600/50"
                            : category === "SECRETS"
                            ? "bg-rose-950/70 text-rose-300 border-rose-600/50"
                            : category === "CONTAINER"
                            ? "bg-sky-950/70 text-sky-300 border-sky-600/50"
                            : category === "IAC"
                            ? "bg-purple-950/70 text-purple-300 border-purple-600/50"
                            : category === "CI_CD"
                            ? "bg-emerald-950/70 text-emerald-300 border-emerald-600/50"
                            : "bg-indigo-950/70 text-indigo-300 border-indigo-600/50"
                        }`}
                      >
                        {category}
                      </span>

                      <p className="text-sm font-mono text-slate-100 font-semibold">{f.ruleId}</p>

                      {f.package && (
                        <span className="text-[11px] font-mono bg-cyan-950/40 text-cyan-300 border border-cyan-800/40 px-2 py-0.5 rounded">
                          📦 {f.package}@{f.installedVersion || "?"}
                          {f.fixedVersion && <span className="text-emerald-400 font-semibold"> → fixed in {f.fixedVersion}</span>}
                        </span>
                      )}

                      {category === "CONTAINER" && (
                        <span className="text-[10px] font-mono bg-sky-950/40 text-sky-300 border border-sky-800/40 px-1.5 py-0.5 rounded flex items-center gap-1">
                          🐳 {f.iacPlatform || "docker"} {f.containerImage ? `(${f.containerImage})` : ""}
                        </span>
                      )}

                      {category === "IAC" && (
                        <span className="text-[10px] font-mono bg-purple-950/40 text-purple-300 border border-purple-800/40 px-1.5 py-0.5 rounded flex items-center gap-1">
                          ☁️ {f.iacPlatform || "IaC"} {f.resourceType ? `· ${f.resourceType}` : ""}
                        </span>
                      )}

                      {category === "CI_CD" && (
                        <span className="text-[10px] font-mono bg-emerald-950/40 text-emerald-300 border border-emerald-800/40 px-1.5 py-0.5 rounded flex items-center gap-1">
                          🤖 {f.workflowName || "Workflow"} {f.actionName ? `· ${f.actionName}` : ""}
                        </span>
                      )}

                      {category === "SECRETS" && (
                        <span className="text-[10px] font-mono bg-rose-950/40 text-rose-300 border border-rose-800/40 px-1.5 py-0.5 rounded flex items-center gap-1">
                          🔒 Masked Secret {f.secretType ? `(${f.secretType.replace(/_/g, " ")})` : ""}
                        </span>
                      )}

                      <span className="text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700 px-1.5 py-0.5 rounded">
                        Occurrences: {f.displayOccurrences || f.occurrences || 1}
                      </span>
                    </div>

                    <p className="text-xs text-slate-400 font-mono mt-1">
                      File: <span className="text-slate-200 font-medium">{f.file}</span> | Line: <span className="text-amber-400 font-semibold">{f.line > 0 ? f.line : "config"}</span>
                    </p>

                    {f.scaRemediation ? (
                      <p className="text-xs text-cyan-300 mt-1 line-clamp-1 max-w-2xl font-mono">
                        💡 {f.scaRemediation}
                      </p>
                    ) : f.ai?.attackScenario ? (
                      <p className="text-xs text-slate-300 mt-1 line-clamp-1 max-w-2xl">
                        {f.ai.attackScenario}
                      </p>
                    ) : null}
                  </div>
                </div>

                <div className="flex items-center gap-3 text-xs shrink-0 self-end sm:self-center">
                  {/* Risk Badge */}
                  {riskScore > 0 && (
                    <span
                      className={`px-2 py-0.5 rounded font-mono font-bold ${
                        riskScore >= 70
                          ? "bg-red-950/60 text-red-400 border border-red-800/40"
                          : riskScore >= 40
                          ? "bg-amber-950/60 text-amber-400 border border-amber-800/40"
                          : "bg-emerald-950/60 text-emerald-400 border border-emerald-800/40"
                      }`}
                    >
                      Risk: {riskScore}/100
                    </span>
                  )}

                  <span className="bg-slate-800 px-2 py-0.5 rounded font-mono uppercase text-[10px] text-slate-300 border border-slate-700">
                    {f.tool}
                  </span>

                  <span
                    className={`px-2 py-0.5 rounded font-semibold text-[11px] uppercase ${
                      rawStatus === "CONFIRMED"
                        ? "bg-red-950/60 text-red-400 border border-red-800/40"
                        : rawStatus === "LIKELY"
                        ? "bg-orange-950/60 text-orange-400 border border-orange-800/40"
                        : rawStatus === "NEEDS_REVIEW"
                        ? "bg-yellow-950/60 text-yellow-400 border border-yellow-800/40"
                        : rawStatus === "FALSE_POSITIVE"
                        ? "bg-emerald-950/60 text-emerald-400 border border-emerald-800/40"
                        : rawStatus === "RESOLVED"
                        ? "bg-purple-950/60 text-purple-400 border border-purple-800/40"
                        : rawStatus === "REMEDIATED"
                        ? "bg-blue-950/60 text-blue-400 border border-blue-800/40"
                        : "bg-amber-950/60 text-amber-400 border border-amber-800/40"
                    }`}
                  >
                    {rawStatus.replace(/_/g, " ")}
                  </span>

                  {f.ai && (
                    <span className="bg-blue-950/60 text-blue-400 border border-blue-800/40 px-2 py-0.5 rounded font-medium">
                      AI: {f.ai.confidence}%
                    </span>
                  )}
                </div>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default Findings;

