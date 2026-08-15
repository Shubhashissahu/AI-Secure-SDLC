import { useEffect, useState, useCallback, useRef } from "react";
import { Link } from "react-router-dom";
import api from "../services/api";
import GateBadge from "../components/GateBadge";
import CreateScanModal from "../components/CreateScanModal";

const STATUS_LABELS = {
  pending: "⏳ Pending",
  scanning: "🔍 Scanning",
  ai_review: "🤖 AI Review",
  completed: "✅ Completed",
  failed: "❌ Failed",
};

function Scans() {
  const [scans, setScans] = useState([]);
  const [repos, setRepos] = useState([]);
  const [selectedRepo, setSelectedRepo] = useState("");
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [error, setError] = useState("");
  const scansRef = useRef(scans);
  scansRef.current = scans;

  const loadRepos = useCallback((signal) => {
    return api
      .get("/api/repositories", { signal })
      .then((res) => {
        const list = res.data?.data || [];
        setRepos(list);
      })
      .catch((err) => {
        if (err.name === "CanceledError" || err.code === "ERR_CANCELED") return;
        console.error("[Scans] Error loading repositories:", err);
      });
  }, []);

  const loadScans = useCallback((signal) => {
    const params = selectedRepo ? { repositoryId: selectedRepo } : {};
    return api
      .get("/api/scans", { params, signal })
      .then((res) => {
        setScans(res.data?.data || []);
        setError("");
      })
      .catch((err) => {
        if (err.name === "CanceledError" || err.code === "ERR_CANCELED") return;
        setError("Failed to load scans. Click Retry to reload.");
      });
  }, [selectedRepo]);

  // Load repositories on mount
  useEffect(() => {
    const controller = new AbortController();
    loadRepos(controller.signal);
    return () => controller.abort();
  }, [loadRepos]);

  // Initial and on-filter change load
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    loadScans(controller.signal).finally(() => setLoading(false));
    return () => controller.abort();
  }, [loadScans]);

  // Poll only when active scans exist
  useEffect(() => {
    const interval = setInterval(() => {
      if (document.visibilityState !== "visible") return;
      const hasActive = scansRef.current.some(
        (s) => s.status === "pending" || s.status === "scanning" || s.status === "ai_review"
      );
      if (hasActive) {
        loadScans();
      }
    }, 8000);

    return () => clearInterval(interval);
  }, [loadScans]);

  function handleScanCreated(newScan) {
    if (newScan) {
      setScans((prev) => [newScan, ...prev.filter((s) => s._id !== newScan._id)]);
    }
  }

  // Helper to extract repository display name from scan
  function getRepoName(scan) {
    if (scan.repositoryId && typeof scan.repositoryId === "object") {
      return `${scan.repositoryId.owner || ""}/${scan.repositoryId.name || ""}`;
    }
    const found = repos.find((r) => (r._id || r.id) === scan.repositoryId);
    return found ? `${found.owner}/${found.name}` : "Repository";
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {showModal && (
        <CreateScanModal
          repos={repos}
          onClose={() => setShowModal(false)}
          onCreated={handleScanCreated}
          onRefreshRepos={loadRepos}
        />
      )}

      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <span>⚡</span> Scans
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Automated multi-scanner execution pipeline records &amp; policy gate evaluations.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            value={selectedRepo}
            onChange={(e) => setSelectedRepo(e.target.value)}
            className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-xs focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All repositories</option>
            {repos.map((r) => {
              const id = r._id || r.id;
              return (
                <option key={id} value={id}>
                  {r.owner}/{r.name}
                </option>
              );
            })}
          </select>
          <button
            onClick={() => {
              loadRepos();
              setShowModal(true);
            }}
            className="btn-primary text-xs flex items-center gap-1.5"
          >
            <span>+</span> New Scan
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-950/40 border border-red-800/40 text-red-300 text-xs rounded-xl p-4 flex items-center justify-between">
          <span>{error}</span>
          <button
            onClick={() => {
              setLoading(true);
              loadScans().finally(() => setLoading(false));
            }}
            className="btn-secondary text-xs px-2.5 py-1"
          >
            Retry
          </button>
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center gap-2 text-slate-400 py-16">
          <span className="animate-spin text-lg">⏳</span> Loading security scans…
        </div>
      ) : scans.length === 0 ? (
        <div className="card text-center py-16 text-slate-400">
          <p className="text-4xl mb-3">🔍</p>
          <p className="text-base font-medium text-white mb-1">No scans recorded yet</p>
          <p className="text-xs text-slate-400 mb-4">
            Register a repository, then start a scan to trigger SAST, Secrets, AI Security &amp; SCA analysis.
          </p>
          <button
            onClick={() => setShowModal(true)}
            className="btn-primary text-xs"
          >
            Start your first scan
          </button>
        </div>
      ) : (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead className="bg-slate-900/80 text-slate-400 text-xs uppercase tracking-wider">
                <tr>
                  <th className="px-4 py-3">Scan ID</th>
                  <th className="px-4 py-3">Repository</th>
                  <th className="px-4 py-3">Commit</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Security Gate</th>
                  <th className="px-4 py-3">Findings</th>
                  <th className="px-4 py-3">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-xs">
                {scans.map((scan) => (
                  <tr key={scan._id} className="hover:bg-slate-800/50 transition-colors">
                    <td className="px-4 py-3 font-mono text-blue-400 font-semibold">
                      <Link to={`/findings?scanId=${scan._id}`} className="hover:underline">
                        #{scan._id?.slice(-6)}
                      </Link>
                    </td>
                    <td className="px-4 py-3 font-medium text-slate-200 font-mono">
                      {getRepoName(scan)}
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-300">
                      {scan.commitSha ? scan.commitSha.slice(0, 7) : "HEAD"}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`text-[11px] font-medium px-2 py-0.5 rounded-full border ${
                          scan.status === "completed"
                            ? "bg-emerald-950/60 text-emerald-300 border-emerald-800/40"
                            : scan.status === "failed"
                            ? "bg-red-950/60 text-red-300 border-red-800/40"
                            : "bg-amber-950/60 text-amber-300 border-amber-800/40"
                        }`}
                      >
                        {STATUS_LABELS[scan.status] || scan.status}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <GateBadge result={scan.gateResult} />
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <Link
                          to={`/findings?scanId=${scan._id}`}
                          className="text-blue-400 hover:text-blue-300 hover:underline font-semibold"
                        >
                          {scan.summary?.total ?? 0} findings
                        </Link>
                        {scan.rescanSummary && (scan.rescanSummary.newFindings > 0 || scan.rescanSummary.resolvedFindings > 0) && (
                          <div className="flex items-center gap-1 text-[10px] font-mono">
                            {scan.rescanSummary.newFindings > 0 && (
                              <span className="bg-red-950/60 text-red-400 border border-red-800/40 px-1 rounded">
                                +{scan.rescanSummary.newFindings}
                              </span>
                            )}
                            {scan.rescanSummary.resolvedFindings > 0 && (
                              <span className="bg-purple-950/60 text-purple-400 border border-purple-800/40 px-1 rounded">
                                -{scan.rescanSummary.resolvedFindings} resolved
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-slate-400">
                      {new Date(scan.startedAt).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

export default Scans;