import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import api from "../services/api";
import SeverityBadge from "../components/SeverityBadge";

const STATUS_OPTIONS = ["CONFIRMED", "LIKELY", "NEEDS_REVIEW", "FALSE_POSITIVE", "REMEDIATED", "RESOLVED"];


function RiskBar({ label, value, max, color = "bg-blue-500" }) {
  const percent = Math.min(100, Math.round((value / max) * 100));
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-xs text-slate-400">
        <span>{label}</span>
        <span className="font-mono text-slate-300">
          {value}/{max}
        </span>
      </div>
      <div className="h-2 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
        <div className={`h-full ${color} transition-all duration-500`} style={{ width: `${percent}%` }} />
      </div>
    </div>
  );
}

function FindingDetail() {
  const { id } = useParams();
  const [finding, setFinding] = useState(null);
  const [loading, setLoading] = useState(true);
  const [updating, setUpdating] = useState(false);
  const [reAnalyzing, setReAnalyzing] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    api
      .get(`/api/findings/${id}`, { signal: controller.signal })
      .then((res) => {
        setFinding(res.data.data);
        setError("");
      })
      .catch((err) => {
        if (err.name === "CanceledError" || err.code === "ERR_CANCELED") return;
        setError("Failed to load vulnerability details.");
      })
      .finally(() => setLoading(false));

    return () => controller.abort();
  }, [id]);

  async function handleStatusChange(newStatus) {
    if (updating) return;
    setUpdating(true);
    try {
      const res = await api.patch(`/api/findings/${id}`, { status: newStatus });
      setFinding(res.data.data);
    } catch {
      setError("Failed to update status.");
    } finally {
      setUpdating(false);
    }
  }

  async function handleRunOllamaReview() {
    if (reAnalyzing) return;
    setReAnalyzing(true);
    setError("");
    try {
      const res = await api.post(`/api/findings/${id}/ai-review`);
      setFinding(res.data.data);
    } catch (err) {
      setError(err.response?.data?.message || err.message || "Failed to run Ollama AI review.");
    } finally {
      setReAnalyzing(false);
    }
  }

  function handleCopyPatch() {
    if (finding?.ai?.remediation?.patch) {
      navigator.clipboard.writeText(finding.ai.remediation.patch);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }

  if (loading) {
    return (
      <div className="space-y-4 animate-pulse max-w-4xl">
        <div className="h-6 bg-slate-800 rounded w-1/3"></div>
        <div className="h-10 bg-slate-800 rounded w-2/3"></div>
        <div className="h-48 bg-slate-800 rounded-xl"></div>
      </div>
    );
  }

  if (error) return <p className="text-red-400 text-xs mb-4">{error}</p>;
  if (!finding) return null;

  const { ai, risk } = finding;

  return (
    <div className="max-w-4xl space-y-6 animate-fade-in">
      {/* Top Navigation & Status bar */}
      <div className="flex items-center justify-between">
        <Link to="/findings" className="text-xs text-slate-400 hover:text-white flex items-center gap-1">
          ← Back to findings
        </Link>
        <div className="flex items-center gap-3">
          <button
            onClick={handleRunOllamaReview}
            disabled={reAnalyzing}
            className="btn-primary text-xs flex items-center gap-2"
          >
            {reAnalyzing ? (
              <>
                <span className="animate-spin">⏳</span>
                <span>Analyzing with AI...</span>
              </>
            ) : (
              <>
                <span>🤖</span>
                <span>Re-run Ollama AI Triage</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Resolution Banner if fixed */}
      {finding.status === "RESOLVED" && (
        <div className="bg-purple-950/60 border border-purple-800/60 rounded-xl p-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-2xl">🎉</span>
            <div>
              <p className="text-sm font-semibold text-purple-200">Vulnerability Automatically Resolved</p>
              <p className="text-xs text-purple-400">
                This vulnerability was verified as fixed in subsequent scan
                {finding.resolvedCommitSha && (
                  <> (Commit: <code className="font-mono bg-purple-900/60 px-1.5 py-0.5 rounded text-purple-200">{finding.resolvedCommitSha.slice(0, 8)}</code>)</>
                )}
                {finding.resolvedAt && <> on {new Date(finding.resolvedAt).toLocaleDateString()}</>}
              </p>
            </div>
          </div>
          <span className="text-xs px-2.5 py-1 bg-purple-900/60 text-purple-200 border border-purple-700/60 rounded-lg font-mono font-bold uppercase">
            RESOLVED
          </span>
        </div>
      )}

      {/* Main Finding Header */}
      <div className="card p-6 gradient-border">
        <div className="flex flex-wrap items-center justify-between gap-4 mb-3">
          <div className="flex items-center gap-3 flex-wrap">
            <SeverityBadge severity={finding.severity} />

            {/* Category Badge */}
            <span
              className={`text-xs font-bold font-mono px-2.5 py-1 rounded border uppercase ${
                finding.category === "SCA"
                  ? "bg-cyan-950/70 text-cyan-300 border-cyan-600/50"
                  : finding.category === "SECRETS"
                  ? "bg-rose-950/70 text-rose-300 border-rose-600/50"
                  : finding.category === "CONTAINER"
                  ? "bg-sky-950/70 text-sky-300 border-sky-600/50"
                  : finding.category === "IAC"
                  ? "bg-purple-950/70 text-purple-300 border-purple-600/50"
                  : finding.category === "CI_CD"
                  ? "bg-emerald-950/70 text-emerald-300 border-emerald-600/50"
                  : "bg-indigo-950/70 text-indigo-300 border-indigo-600/50"
              }`}
            >
              {finding.category || (
                finding.tool === "gitleaks" || finding.tool === "secret-scanner" ? "SECRETS" :
                finding.tool === "container-scanner" ? "CONTAINER" :
                finding.tool === "iac-scanner" ? "IAC" :
                finding.tool === "cicd-scanner" ? "CI_CD" :
                finding.tool === "trivy" || finding.tool === "osv" ? "SCA" : "SAST"
              )}
            </span>

            <span className="text-xs font-mono bg-slate-800 text-slate-300 border border-slate-700 rounded px-2.5 py-1 uppercase">
              {finding.tool}
            </span>
            <span className="text-xs font-mono bg-slate-800 text-slate-400 border border-slate-700 rounded px-2 py-1">
              Occurrences: {finding.occurrences || 1}
            </span>
            {(finding.cve || ai?.cwe || finding.cwe) && (
              <span className="text-xs font-mono bg-indigo-950/60 text-indigo-300 border border-indigo-800/40 rounded px-2.5 py-1 font-semibold">
                {finding.cve || ai?.cwe || finding.cwe}
              </span>
            )}
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 mr-1">Status:</span>
            {STATUS_OPTIONS.map((s) => {
              const currentStatus = (finding.status || "OPEN").toUpperCase();
              const isSelected = currentStatus === s;
              return (
                <button
                  key={s}
                  disabled={updating || isSelected}
                  onClick={() => handleStatusChange(s)}
                  className={`text-xs px-2.5 py-1 rounded-lg border capitalize transition-all ${
                    isSelected
                      ? "bg-blue-600 border-blue-500 text-white font-semibold shadow-md shadow-blue-500/20"
                      : "border-slate-700/60 text-slate-400 hover:border-slate-500 hover:text-white"
                  }`}
                >
                  {s.replace("_", " ")}
                </button>
              );
            })}
          </div>

        </div>

        <h1 className="text-xl font-mono text-white font-bold break-all mb-2">
          {finding.file}:{finding.line > 0 ? <span className="text-amber-400">{finding.line}</span> : <span className="text-slate-400">manifest</span>}
        </h1>
        <div className="flex flex-wrap items-center gap-4 text-xs text-slate-400 font-mono">
          <span>Rule / CVE: <strong className="text-slate-200">{finding.cve || finding.ruleId}</strong></span>
          {finding.scanId && (
            <span>Scan: <Link to={`/scans`} className="text-blue-400 hover:underline">#{typeof finding.scanId === "object" ? finding.scanId._id.slice(-6) : String(finding.scanId).slice(-6)}</Link></span>
          )}
          {finding.commitSha && (
            <span>Commit: <strong className="text-slate-300">{finding.commitSha.slice(0, 7)}</strong></span>
          )}
        </div>
      </div>

      {/* Container Security Card */}
      {(finding.category === "CONTAINER" || finding.tool === "container-scanner") && (
        <div className="card p-6 border-sky-800/40 bg-sky-950/10 space-y-4">
          <div className="flex items-center justify-between border-b border-sky-800/30 pb-3">
            <h3 className="text-sm font-semibold text-sky-300 flex items-center gap-2">
              <span>🐳</span> Container Security & Dockerfile Analysis
            </h3>
            {finding.complianceStandard && (
              <span className="text-xs bg-sky-900/60 text-sky-200 border border-sky-600/50 px-2.5 py-1 rounded font-mono font-semibold">
                {finding.complianceStandard}
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">Platform / Target</span>
              <span className="font-mono text-slate-100 font-bold text-sm capitalize">{finding.iacPlatform || "Docker"}</span>
            </div>

            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">Base Image / Resource</span>
              <span className="font-mono text-amber-400 font-bold text-sm">{finding.containerImage || "Local Build"}</span>
            </div>

            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">Compliance Policy</span>
              <span className="font-mono text-sky-300 font-bold text-sm">CIS Docker Benchmark</span>
            </div>
          </div>

          {finding.scaRemediation && (
            <div className="bg-sky-950/40 border border-sky-700/40 rounded-lg p-3">
              <span className="text-[10px] font-bold text-sky-300 uppercase tracking-wider block mb-1">
                Hardening Recommendation:
              </span>
              <p className="text-xs font-mono text-sky-100 font-semibold">{finding.scaRemediation}</p>
            </div>
          )}
        </div>
      )}

      {/* IaC Security Card */}
      {(finding.category === "IAC" || finding.tool === "iac-scanner") && (
        <div className="card p-6 border-purple-800/40 bg-purple-950/10 space-y-4">
          <div className="flex items-center justify-between border-b border-purple-800/30 pb-3">
            <h3 className="text-sm font-semibold text-purple-300 flex items-center gap-2">
              <span>☁️</span> Infrastructure as Code (IaC) Security Details
            </h3>
            {finding.complianceStandard && (
              <span className="text-xs bg-purple-900/60 text-purple-200 border border-purple-600/50 px-2.5 py-1 rounded font-mono font-semibold">
                {finding.complianceStandard}
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">IaC Technology</span>
              <span className="font-mono text-slate-100 font-bold text-sm capitalize">{finding.iacPlatform || "Terraform / K8s"}</span>
            </div>

            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">Flagged Resource</span>
              <span className="font-mono text-purple-300 font-bold text-sm">{finding.resourceType || finding.resourceName || "Infrastructure Component"}</span>
            </div>

            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">Security Standard</span>
              <span className="font-mono text-emerald-400 font-bold text-sm">CIS Cloud Security</span>
            </div>
          </div>

          {finding.scaRemediation && (
            <div className="bg-purple-950/40 border border-purple-700/40 rounded-lg p-3">
              <span className="text-[10px] font-bold text-purple-300 uppercase tracking-wider block mb-1">
                Remediation Guidance:
              </span>
              <p className="text-xs font-mono text-purple-100 font-semibold">{finding.scaRemediation}</p>
            </div>
          )}
        </div>
      )}

      {/* CI/CD Pipeline Security Card */}
      {(finding.category === "CI_CD" || finding.tool === "cicd-scanner") && (
        <div className="card p-6 border-emerald-800/40 bg-emerald-950/10 space-y-4">
          <div className="flex items-center justify-between border-b border-emerald-800/30 pb-3">
            <h3 className="text-sm font-semibold text-emerald-300 flex items-center gap-2">
              <span>🤖</span> CI/CD Workflow & GitHub Actions Security Analysis
            </h3>
            {finding.complianceStandard && (
              <span className="text-xs bg-emerald-900/60 text-emerald-200 border border-emerald-600/50 px-2.5 py-1 rounded font-mono font-semibold">
                {finding.complianceStandard}
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">Target Workflow</span>
              <span className="font-mono text-slate-100 font-bold text-sm">{finding.workflowName || "GitHub Actions"}</span>
            </div>

            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">Referenced Action</span>
              <span className="font-mono text-emerald-400 font-bold text-sm">{finding.actionName || "Inline Step / Runner"}</span>
            </div>

            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">Compliance Benchmark</span>
              <span className="font-mono text-cyan-300 font-bold text-sm">OpenSSF Scorecard / CIS</span>
            </div>
          </div>

          {finding.scaRemediation && (
            <div className="bg-emerald-950/40 border border-emerald-700/40 rounded-lg p-3">
              <span className="text-[10px] font-bold text-emerald-300 uppercase tracking-wider block mb-1">
                Workflow Hardening Remediation:
              </span>
              <p className="text-xs font-mono text-emerald-100 font-semibold">{finding.scaRemediation}</p>
            </div>
          )}
        </div>
      )}

      {/* SCA Dependency Card if finding is SCA */}
      {(finding.category === "SCA" || finding.package) && (
        <div className="card p-6 border-cyan-800/40 bg-cyan-950/10 space-y-4">
          <div className="flex items-center justify-between border-b border-cyan-800/30 pb-3">
            <h3 className="text-sm font-semibold text-cyan-300 flex items-center gap-2">
              <span>📦</span> Software Composition Analysis (SCA) Dependency Details
            </h3>
            {finding.cvss && (
              <span className="text-xs bg-amber-950/60 text-amber-300 border border-amber-600/50 px-2.5 py-1 rounded font-mono font-bold">
                CVSS Base Score: {finding.cvss}/10
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 text-xs">
            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">Vulnerable Package</span>
              <span className="font-mono text-slate-100 font-bold text-sm">{finding.package || "N/A"}</span>
            </div>

            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">Installed Version</span>
              <span className="font-mono text-red-400 font-bold text-sm">{finding.installedVersion || "N/A"}</span>
            </div>

            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">Fixed in Version</span>
              <span className="font-mono text-emerald-400 font-bold text-sm">
                {finding.fixedVersion ? `>= ${finding.fixedVersion}` : "No patch yet"}
              </span>
            </div>

            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">CVE / Advisory</span>
              <span className="font-mono text-indigo-300 font-bold text-sm">
                {finding.cve || finding.ruleId}
              </span>
            </div>
          </div>

          {finding.scaRemediation && (
            <div className="bg-cyan-950/40 border border-cyan-700/40 rounded-lg p-3">
              <span className="text-[10px] font-bold text-cyan-300 uppercase tracking-wider block mb-1">
                Remediation & Upgrade Instruction:
              </span>
              <p className="text-xs font-mono text-cyan-100 font-semibold">{finding.scaRemediation}</p>
            </div>
          )}
        </div>
      )}

      {/* Secret Detection Card if finding is SECRETS */}
      {(finding.category === "SECRETS" || finding.tool === "gitleaks") && (
        <div className="card p-6 border-rose-800/40 bg-rose-950/10 space-y-4">
          <div className="flex items-center justify-between border-b border-rose-800/30 pb-3">
            <h3 className="text-sm font-semibold text-rose-300 flex items-center gap-2">
              <span>🔑</span> Secret Scanner Detection & Masking
            </h3>
            <span className="text-xs bg-rose-900/60 text-rose-200 border border-rose-700/60 px-2.5 py-1 rounded font-mono font-bold uppercase">
              MASKED IN UI & LOGS
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">Detected Secret Type</span>
              <span className="font-mono text-rose-300 font-bold text-sm capitalize">
                {(finding.secretType || "Credential").replace(/_/g, " ")}
              </span>
            </div>

            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">Security Action Required</span>
              <span className="font-mono text-amber-400 font-bold text-sm">Immediate Key Revocation & Rotation</span>
            </div>
          </div>
        </div>
      )}


      {/* Side-by-side Code Comparison: Vulnerable Code vs Automated Remediation */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Vulnerable Code (Before) */}
        <div className="card p-5 border-red-900/40 bg-red-950/10">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-bold uppercase tracking-wider text-red-400 flex items-center gap-1.5">
              <span>⚠️</span> Flagged Vulnerable Code (Before)
            </span>
            <span className="text-[10px] font-mono text-slate-500">Line {finding.line}</span>
          </div>
          <pre className="text-xs font-mono bg-slate-950 border border-red-900/30 rounded-lg p-4 overflow-x-auto whitespace-pre-wrap text-red-300">
            {finding.codeSnippet}
          </pre>
        </div>

        {/* Secure Remediation Patch (After) */}
        <div className="card p-5 border-emerald-900/40 bg-emerald-950/10">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
              <span>✅</span> AI Suggested Secure Code (After)
            </span>
            {(ai?.remediation?.patch || ai?.secureFix) && (
              <button
                onClick={() => {
                  navigator.clipboard.writeText(ai?.remediation?.patch || ai?.secureFix);
                  setCopied(true);
                  setTimeout(() => setCopied(false), 2000);
                }}
                className="text-[10px] bg-emerald-900/40 hover:bg-emerald-800/40 text-emerald-300 border border-emerald-700/40 px-2 py-0.5 rounded transition-all"
              >
                {copied ? "Copied! ✓" : "Copy Secure Code"}
              </button>
            )}
          </div>
          {(ai?.remediation?.patch || ai?.secureFix) ? (
            <pre className="text-xs font-mono bg-slate-950 border border-emerald-900/30 rounded-lg p-4 overflow-x-auto whitespace-pre-wrap text-emerald-300">
              {ai.remediation?.patch || ai.secureFix}
            </pre>
          ) : (
            <div className="text-xs text-slate-500 py-6 text-center italic">
              No automated patch available for this finding.
            </div>
          )}
        </div>
      </div>

      {/* AI Vulnerability Analysis */}
      {ai && (
        <div className="card p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <span>🤖</span> AI Security Triage & Attack Scenario
            </h3>
            <span
              className={`text-xs px-2.5 py-0.5 rounded-full border font-semibold ${
                ai.isRealVulnerability
                  ? "border-red-500/40 text-red-400 bg-red-950/40"
                  : "border-emerald-500/40 text-emerald-400 bg-emerald-950/40"
              }`}
            >
              {ai.isRealVulnerability ? "Real Vulnerability" : "False Positive"} · {ai.confidence}% Confidence
            </span>
          </div>

          <div>
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-1">
              Exploit / Attack Scenario
            </span>
            <p className="text-xs text-slate-200 leading-relaxed bg-slate-900/60 border border-slate-800 rounded-lg p-3">
              {ai.attackScenario}
            </p>
          </div>

          {ai.remediation?.explanation && (
            <div>
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                Remediation Guidance
              </span>
              <p className="text-xs text-slate-300 leading-relaxed italic bg-slate-900/40 border border-slate-800 rounded-lg p-3">
                {ai.remediation.explanation}
              </p>
            </div>
          )}

          <div className="grid grid-cols-3 gap-4 pt-2 text-xs">
            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">CWE Weakness</span>
              <span className="font-mono text-slate-200 font-semibold">{ai.cwe}</span>
            </div>
            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">OWASP Category</span>
              <span className="font-mono text-slate-200 font-semibold truncate block">{ai.owasp}</span>
            </div>
            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">Exploitability</span>
              <span className="font-mono text-amber-400 font-bold uppercase">{ai.exploitability}</span>
            </div>
          </div>
        </div>
      )}

      {/* Risk Assessment Breakdown */}
      {risk && (
        <div className="card p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <span>📊</span> Calculated Risk Score
            </h3>
            <span className="text-2xl font-black text-amber-400 font-mono">
              {risk.score}<span className="text-xs text-slate-500 font-normal">/100</span>
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <RiskBar label="Scanner Severity Weight" value={risk.severityWeight} max={40} color="bg-red-500" />
            <RiskBar label="Exploitability Weight" value={risk.exploitabilityWeight} max={30} color="bg-orange-500" />
            <RiskBar label="Business Impact Weight" value={risk.businessImpactWeight} max={20} color="bg-amber-500" />
            <RiskBar label="Exposure Weight" value={risk.exposureWeight} max={10} color="bg-emerald-500" />
          </div>
        </div>
      )}
    </div>
  );
}

export default FindingDetail;