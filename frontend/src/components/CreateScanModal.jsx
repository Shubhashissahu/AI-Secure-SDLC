import { useState, useEffect } from "react";
import api from "../services/api";

export default function CreateScanModal({ repos = [], onClose, onCreated, onRefreshRepos }) {
  const [localRepos, setLocalRepos] = useState(repos);
  const [loadingRepos, setLoadingRepos] = useState(repos.length === 0);
  const [form, setForm] = useState({
    repositoryId: repos[0]?._id || repos[0]?.id || "",
    prNumber: "",
    commitSha: "",
    triggeredBy: "manual",
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (repos && repos.length > 0) {
      setLocalRepos(repos);
      setLoadingRepos(false);
      setForm((prev) => ({
        ...prev,
        repositoryId: prev.repositoryId || repos[0]._id || repos[0].id || ""
      }));
    } else {
      let isMounted = true;
      setLoadingRepos(true);
      api
        .get("/api/repositories")
        .then((res) => {
          if (!isMounted) return;
          const list = res.data?.data || [];
          setLocalRepos(list);
          if (list.length > 0) {
            setForm((prev) => ({
              ...prev,
              repositoryId: prev.repositoryId || list[0]._id || list[0].id || ""
            }));
          }
        })
        .catch((err) => {
          if (!isMounted) return;
          console.error("[CreateScanModal] Failed to fetch repositories:", err);
          setError("Unable to load repositories.");
        })
        .finally(() => {
          if (isMounted) setLoadingRepos(false);
        });

      return () => {
        isMounted = false;
      };
    }
  }, [repos]);

  async function handleSubmit(e) {
    e.preventDefault();
    if (submitting) return;

    if (!form.repositoryId) {
      setError("Please select a registered repository.");
      return;
    }

    setError("");
    setSubmitting(true);
    try {
      const createRes = await api.post("/api/scans", {
        repositoryId: form.repositoryId,
        prNumber: Number(form.prNumber),
        commitSha: form.commitSha.trim(),
        triggeredBy: form.triggeredBy || "manual",
      });
      const scanId = createRes.data?.data?._id || createRes.data?.data?.id;

      if (scanId) {
        await api.post(`/api/scans/${scanId}/run`);
      }

      onCreated(createRes.data.data);
      if (onRefreshRepos) onRefreshRepos();
      onClose();
    } catch (err) {
      console.error("[CreateScanModal] Error starting scan:", err);
      setError(
        err.response?.data?.message || err.message || "Failed to create scan."
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 animate-fade-in">
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 w-full max-w-md shadow-2xl animate-fade-in-up">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-lg font-bold flex items-center gap-2">
            <span>🔍</span> New Scan
          </h2>
          <button
            onClick={onClose}
            disabled={submitting}
            className="text-slate-400 hover:text-white text-xl transition-colors"
          >
            ✕
          </button>
        </div>

        {error && (
          <div className="bg-red-900/30 border border-red-700 text-red-300 text-sm rounded-lg px-4 py-3 mb-4">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="block text-sm text-slate-400">Repository</label>
              {loadingRepos && (
                <span className="text-[11px] text-blue-400 animate-pulse flex items-center gap-1">
                  <span>⏳</span> Fetching repos...
                </span>
              )}
            </div>
            <select
              required
              disabled={submitting || loadingRepos || localRepos.length === 0}
              value={form.repositoryId}
              onChange={(e) => setForm({ ...form, repositoryId: e.target.value })}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              {loadingRepos ? (
                <option value="">Loading registered repositories...</option>
              ) : localRepos.length === 0 ? (
                <option value="">No repositories — register one first</option>
              ) : (
                localRepos.map((r) => {
                  const id = r._id || r.id;
                  return (
                    <option key={id} value={id}>
                      {r.owner}/{r.name}
                    </option>
                  );
                })
              )}
            </select>
          </div>

          <div>
            <label className="block text-sm text-slate-400 mb-1">PR Number</label>
            <input
              required
              disabled={submitting}
              type="number"
              min="1"
              placeholder="e.g. 42"
              value={form.prNumber}
              onChange={(e) => setForm({ ...form, prNumber: e.target.value })}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm text-slate-400 mb-1">
              Commit SHA <span className="text-slate-500 text-xs">(min 7 chars)</span>
            </label>
            <input
              required
              disabled={submitting}
              minLength={7}
              maxLength={40}
              placeholder="e.g. a1b2c3d or HEAD"
              value={form.commitSha}
              onChange={(e) => setForm({ ...form, commitSha: e.target.value })}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm text-slate-400 mb-1">Triggered By</label>
            <input
              disabled={submitting}
              value={form.triggeredBy}
              onChange={(e) => setForm({ ...form, triggeredBy: e.target.value })}
              placeholder="e.g. manual, ci-bot"
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div className="flex gap-3 pt-2">
            <button
              type="submit"
              disabled={submitting || loadingRepos || localRepos.length === 0}
              className="flex-1 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg px-4 py-2 text-sm font-semibold transition-colors flex items-center justify-center gap-2"
            >
              {submitting ? (
                <>
                  <span className="animate-spin">⏳</span> Starting scan…
                </>
              ) : (
                <>
                  <span>🚀</span> Start Scan
                </>
              )}
            </button>
            <button
              type="button"
              onClick={onClose}
              disabled={submitting}
              className="px-4 py-2 text-sm text-slate-400 hover:text-white border border-slate-700 rounded-lg transition-colors"
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
