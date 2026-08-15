import { useEffect, useState, useCallback, useRef } from "react";
import { Link } from "react-router-dom";
import api, { getCached } from "../services/api";
import SecurityScoreGauge from "../components/SecurityScoreGauge";
import SeverityDistributionChart from "../components/SeverityDistributionChart";
import ScanTimeline from "../components/ScanTimeline";
import GateBadge from "../components/GateBadge";

function MetricCard({ title, value, subtitle, icon, colorClass = "text-blue-400" }) {
  return (
    <div className="stat-card p-4 rounded-xl border border-slate-800 bg-slate-900/60 shadow-lg">
      <div className="flex items-center justify-between mb-2">
        <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">{title}</span>
        <span className={`text-lg ${colorClass}`}>{icon}</span>
      </div>
      <div className="text-2xl font-extrabold tracking-tight text-white mb-0.5 animate-count-up font-mono">{value}</div>
      {subtitle && <p className="text-[11px] text-slate-400 truncate">{subtitle}</p>}
    </div>
  );
}

function Dashboard() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const isFetchingRef = useRef(false);

  const loadData = useCallback((signal, isManual = false) => {
    if (isFetchingRef.current && !isManual) return Promise.resolve();
    isFetchingRef.current = true;

    const fetcher = isManual
      ? api.get("/api/dashboard/stats", { signal }).catch(() => api.get("/api/dashboard", { signal }))
      : getCached("/api/dashboard/stats", { signal }, 5000).catch(() => api.get("/api/dashboard", { signal }));

    return fetcher
      .then((res) => {
        const payload = res.data?.data || res.data;
        if (payload) {
          setStats(payload);
          setError("");
        }
      })
      .catch((err) => {
        if (err.name === "CanceledError" || err.code === "ERR_CANCELED") return;
        console.error("Failed to load dashboard stats:", err);
        setError("Unable to load live dashboard statistics. Click 'Sync Live DB' or 'Retry' to reload.");
      })
      .finally(() => {
        isFetchingRef.current = false;
      });
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    loadData(controller.signal).finally(() => setLoading(false));
    return () => controller.abort();
  }, [loadData]);

  // Auto-refresh every 20s (only when document is visible and not hidden)
  useEffect(() => {
    const interval = setInterval(() => {
      if (document.visibilityState === "visible") {
        loadData();
      }
    }, 20000);

    return () => clearInterval(interval);
  }, [loadData]);

  function handleRefresh() {
    setRefreshing(true);
    loadData(undefined, true).finally(() => setRefreshing(false));
  }

  if (loading) {
    return (
      <div className="space-y-6 animate-pulse">
        <div className="h-8 bg-slate-800 rounded w-1/4"></div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="h-24 bg-slate-800 rounded-xl"></div>
          <div className="h-24 bg-slate-800 rounded-xl"></div>
          <div className="h-24 bg-slate-800 rounded-xl"></div>
          <div className="h-24 bg-slate-800 rounded-xl"></div>
        </div>
      </div>
    );
  }

  const overview = stats?.overview || {};
  const severity = stats?.severity || {};
  const topFiles = stats?.topVulnerableFiles || [];
  const recentScans = stats?.recentScans || [];

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight text-white flex items-center gap-3">
            <span>🛡️</span> AI Secure SDLC Command Center
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time live multi-scanner intelligence (SAST, SCA, Secrets, Container, IaC, CI/CD) and automated AI triage.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="btn-secondary flex items-center gap-2 text-xs"
          >
            <span className={refreshing ? "animate-spin" : ""}>🔄</span>
            {refreshing ? "Refreshing…" : "Sync Live DB"}
          </button>
          <Link to="/findings" className="btn-primary flex items-center gap-2 text-xs">
            <span>🔍</span> View Findings
          </Link>
        </div>
      </div>

      {error && (
        <div className="bg-red-950/40 border border-red-800/40 rounded-xl p-4 text-xs text-red-300 flex items-center justify-between">
          <span>{error}</span>
          <button
            onClick={() => handleRefresh()}
            className="btn-secondary text-xs px-2.5 py-1"
          >
            Retry
          </button>
        </div>
      )}

      {/* Primary Key Metrics Grid (12 Live Metrics calculated from DB) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 stagger-children">
        <MetricCard
          title="Repositories"
          value={overview.totalRepositories || 0}
          subtitle="Monitored codebases"
          icon="📁"
          colorClass="text-blue-400"
        />
        <MetricCard
          title="Total Scans"
          value={overview.totalScans || 0}
          subtitle="Pipeline executions"
          icon="⚡"
          colorClass="text-indigo-400"
        />
        <MetricCard
          title="Total Findings"
          value={overview.totalFindings || 0}
          subtitle="Discovered issues"
          icon="🚨"
          colorClass="text-purple-400"
        />
        <MetricCard
          title="Critical"
          value={overview.critical || severity.critical || 0}
          subtitle="Immediate block"
          icon="🔴"
          colorClass="text-red-400"
        />
        <MetricCard
          title="High"
          value={overview.high || severity.high || 0}
          subtitle="High priority fix"
          icon="🟠"
          colorClass="text-orange-400"
        />
        <MetricCard
          title="Medium / Low"
          value={`${overview.medium || 0} / ${overview.low || 0}`}
          subtitle="Medium & Low"
          icon="🟡"
          colorClass="text-amber-400"
        />
        <MetricCard
          title="Average Risk"
          value={`${overview.averageRisk || stats?.riskStats?.averageRisk || 0}/100`}
          subtitle={`Max Risk: ${stats?.riskStats?.maxRisk || 0}`}
          icon="📊"
          colorClass="text-fuchsia-400"
        />
        <MetricCard
          title="Open Findings"
          value={overview.openFindings || 0}
          subtitle="Active backlog"
          icon="🔓"
          colorClass="text-amber-300"
        />
        <MetricCard
          title="Remediated"
          value={overview.remediatedFindings || 0}
          subtitle="Patched & Resolved"
          icon="✅"
          colorClass="text-emerald-400"
        />
        <MetricCard
          title="False Positives"
          value={overview.falsePositives || 0}
          subtitle="AI Filtered"
          icon="🛡️"
          colorClass="text-slate-400"
        />
        <MetricCard
          title="CI Gate Pass Rate"
          value={`${overview.gatePassRate || 100}%`}
          subtitle="Merge gate success"
          icon="🚦"
          colorClass="text-emerald-300"
        />
        <MetricCard
          title="Security Score"
          value={`${overview.securityScore || 100}/100`}
          subtitle="Overall health"
          icon="🏆"
          colorClass="text-cyan-400"
        />
      </div>

      {/* Security Engine 7 Pillars Breakdown: SAST, AI_SECURITY, SCA, SECRETS, CONTAINER, IAC, CI_CD */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
            <span>🔬</span> Security Engine Breakdown (7 Pillars)
          </h3>
          <Link to="/findings" className="text-[11px] text-blue-400 hover:underline font-mono">
            Filter all →
          </Link>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7 gap-3">
          <Link
            to="/findings?category=SAST"
            className="card p-3.5 border-indigo-800/40 bg-indigo-950/10 hover:bg-indigo-950/20 transition-all group"
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[11px] font-bold uppercase tracking-wider text-indigo-300 flex items-center gap-1">
                <span>🔬</span> SAST
              </span>
              <span className="text-xs text-indigo-400 group-hover:translate-x-0.5 transition-transform">→</span>
            </div>
            <div className="text-2xl font-black text-white font-mono">{overview.sastCount || stats?.categoryDistribution?.SAST || 0}</div>
            <p className="text-[10px] text-slate-400 mt-1">Code flaws (AST/Semgrep)</p>
          </Link>

          <Link
            to="/findings?category=AI_SECURITY"
            className="card p-3.5 border-purple-800/40 bg-purple-950/10 hover:bg-purple-950/20 transition-all group"
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[11px] font-bold uppercase tracking-wider text-purple-300 flex items-center gap-1">
                <span>🤖</span> AI SECURITY
              </span>
              <span className="text-xs text-purple-400 group-hover:translate-x-0.5 transition-transform">→</span>
            </div>
            <div className="text-2xl font-black text-white font-mono">{overview.aiSecurityCount || stats?.categoryDistribution?.AI_SECURITY || 0}</div>
            <p className="text-[10px] text-slate-400 mt-1">Prompt Injection & LLM</p>
          </Link>

          <Link
            to="/findings?category=SCA"
            className="card p-3.5 border-cyan-800/40 bg-cyan-950/10 hover:bg-cyan-950/20 transition-all group"
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[11px] font-bold uppercase tracking-wider text-cyan-300 flex items-center gap-1">
                <span>📦</span> SCA
              </span>
              <span className="text-xs text-cyan-400 group-hover:translate-x-0.5 transition-transform">→</span>
            </div>
            <div className="text-2xl font-black text-white font-mono">{overview.scaCount || stats?.categoryDistribution?.SCA || 0}</div>
            <p className="text-[10px] text-slate-400 mt-1">Packages (OSV/Trivy)</p>
          </Link>

          <Link
            to="/findings?category=SECRETS"
            className="card p-3.5 border-rose-800/40 bg-rose-950/10 hover:bg-rose-950/20 transition-all group"
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[11px] font-bold uppercase tracking-wider text-rose-300 flex items-center gap-1">
                <span>🔑</span> SECRETS
              </span>
              <span className="text-xs text-rose-400 group-hover:translate-x-0.5 transition-transform">→</span>
            </div>
            <div className="text-2xl font-black text-white font-mono">{overview.secretsCount || stats?.categoryDistribution?.SECRETS || 0}</div>
            <p className="text-[10px] text-slate-400 mt-1">Masked credentials</p>
          </Link>

          <Link
            to="/findings?category=CONTAINER"
            className="card p-3.5 border-sky-800/40 bg-sky-950/10 hover:bg-sky-950/20 transition-all group"
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[11px] font-bold uppercase tracking-wider text-sky-300 flex items-center gap-1">
                <span>🐳</span> CONTAINER
              </span>
              <span className="text-xs text-sky-400 group-hover:translate-x-0.5 transition-transform">→</span>
            </div>
            <div className="text-2xl font-black text-white font-mono">{overview.containerCount || stats?.categoryDistribution?.CONTAINER || 0}</div>
            <p className="text-[10px] text-slate-400 mt-1">Docker & Compose</p>
          </Link>

          <Link
            to="/findings?category=IAC"
            className="card p-3.5 border-amber-800/40 bg-amber-950/10 hover:bg-amber-950/20 transition-all group"
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[11px] font-bold uppercase tracking-wider text-amber-300 flex items-center gap-1">
                <span>☁️</span> IAC
              </span>
              <span className="text-xs text-amber-400 group-hover:translate-x-0.5 transition-transform">→</span>
            </div>
            <div className="text-2xl font-black text-white font-mono">{overview.iacCount || stats?.categoryDistribution?.IAC || 0}</div>
            <p className="text-[10px] text-slate-400 mt-1">Terraform & K8s</p>
          </Link>

          <Link
            to="/findings?category=CI_CD"
            className="card p-3.5 border-emerald-800/40 bg-emerald-950/10 hover:bg-emerald-950/20 transition-all group"
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[11px] font-bold uppercase tracking-wider text-emerald-300 flex items-center gap-1">
                <span>⚙️</span> CI/CD
              </span>
              <span className="text-xs text-emerald-400 group-hover:translate-x-0.5 transition-transform">→</span>
            </div>
            <div className="text-2xl font-black text-white font-mono">{overview.cicdCount || stats?.categoryDistribution?.CI_CD || 0}</div>
            <p className="text-[10px] text-slate-400 mt-1">GitHub Actions</p>
          </Link>
        </div>
      </div>

      {/* Main Grid: Gauge + Charts (Severity Trend & Vulnerability Activity) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Security Score Gauge */}
        <div className="card p-6 flex flex-col items-center justify-center gradient-border text-center">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">
            Overall Security Posture
          </h3>
          <SecurityScoreGauge score={overview.securityScore || 0} size={190} />
          <p className="text-xs text-slate-400 mt-4 max-w-xs">
            Score is calculated dynamically based on severity weights, exploitability, and business impact across SAST, SCA, Secrets, Containers, IaC, and CI/CD.
          </p>
        </div>

        {/* Severity Distribution Donut Chart */}
        <div className="card p-6 flex flex-col justify-between">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">
            Vulnerability Severity Breakdown
          </h3>
          <SeverityDistributionChart data={stats?.severityChartData || []} />
          <div className="grid grid-cols-4 gap-2 pt-3 border-t border-slate-800 text-center text-xs">
            <div>
              <span className="block text-red-400 font-bold">{severity.critical || 0}</span>
              <span className="text-slate-500 text-[10px]">Critical</span>
            </div>
            <div>
              <span className="block text-orange-400 font-bold">{severity.high || 0}</span>
              <span className="text-slate-500 text-[10px]">High</span>
            </div>
            <div>
              <span className="block text-amber-400 font-bold">{severity.medium || 0}</span>
              <span className="text-slate-500 text-[10px]">Medium</span>
            </div>
            <div>
              <span className="block text-emerald-400 font-bold">{severity.low || 0}</span>
              <span className="text-slate-500 text-[10px]">Low</span>
            </div>
          </div>
        </div>

        {/* Scan Activity & Severity Trend */}
        <div className="card p-6 flex flex-col justify-between">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">
            Severity &amp; Vulnerability Trend
          </h3>
          <ScanTimeline data={stats?.scanTimeline || []} />
          <div className="text-right text-[11px] text-slate-400 pt-2 border-t border-slate-800">
            Last {stats?.scanTimeline?.length || 0} automated pipeline executions
          </div>
        </div>
      </div>

      {/* Bottom Grid: Top Vulnerable Files + Recent Scans */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Vulnerable Files */}
        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
              🔥 Security Hotspots (Top Vulnerable Files)
            </h3>
            <Link to="/findings" className="text-xs text-blue-400 hover:underline">
              View findings →
            </Link>
          </div>
          {topFiles.length === 0 ? (
            <p className="text-xs text-slate-500 py-6 text-center">No hotspot files detected yet.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>File Path</th>
                    <th className="text-center">Findings</th>
                    <th className="text-right">Max Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {topFiles.map((item, idx) => (
                    <tr key={idx}>
                      <td className="font-mono text-xs text-slate-200 truncate max-w-[200px]" title={item.file}>
                        {item.file}
                      </td>
                      <td className="text-center">
                        <span className="bg-slate-800 text-slate-300 px-2 py-0.5 rounded text-xs font-semibold">
                          {item.findingCount}
                        </span>
                      </td>
                      <td className="text-right">
                        <span
                          className={`font-bold text-xs ${
                            item.maxRiskScore >= 70
                              ? "text-red-400"
                              : item.maxRiskScore >= 40
                              ? "text-amber-400"
                              : "text-emerald-400"
                          }`}
                        >
                          {item.maxRiskScore}/100
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Recent Scans */}
        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
              ⚡ Recent Pipeline Executions
            </h3>
            <Link to="/scans" className="text-xs text-blue-400 hover:underline">
              View all scans →
            </Link>
          </div>
          {recentScans.length === 0 ? (
            <p className="text-xs text-slate-500 py-6 text-center">
              No scans yet. Trigger a scan via PR or API.
            </p>
          ) : (
            <div className="divide-y divide-slate-800/60">
              {recentScans.map((scan) => (
                <Link
                  key={scan._id}
                  to={`/findings?scanId=${scan._id}`}
                  className="flex items-center justify-between py-3 hover:bg-white/5 px-2 rounded-lg transition-colors"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-semibold text-slate-200">
                        PR #{scan.prNumber}
                      </span>
                      <span className="text-[10px] font-mono text-slate-500">
                        ({scan.commitSha?.slice(0, 7)})
                      </span>
                    </div>
                    <span className="text-[10px] text-slate-400">
                      {new Date(scan.startedAt).toLocaleString()}
                    </span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-slate-400 font-mono">
                      {scan.summary?.total || 0} issues
                    </span>
                    <GateBadge result={scan.gateResult} />
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default Dashboard;