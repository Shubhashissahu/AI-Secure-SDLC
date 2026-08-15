import { useEffect, useState, useCallback } from "react";
import api from "../services/api";

function Repositories() {
    const [repos, setRepos] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showForm, setShowForm] = useState(false);
    const [form, setForm] = useState({ name: "", owner: "", githubUrl: "", defaultBranch: "main" });
    const [submitting, setSubmitting] = useState(false);
    const [error, setError] = useState("");
    const [newSecret, setNewSecret] = useState(null);
    const [selectedRepoForPolicy, setSelectedRepoForPolicy] = useState(null);
    const [policyForm, setPolicyForm] = useState(null);
    const [savingPolicy, setSavingPolicy] = useState(false);

    const loadRepos = useCallback((signal) => {
        setLoading(true);
        return api.get("/api/repositories", { signal })
            .then((res) => {
                setRepos(res.data.data || []);
                setError("");
            })
            .catch((err) => {
                if (err.name === "CanceledError" || err.code === "ERR_CANCELED") return;
                setError("Failed to load repositories.");
            })
            .finally(() => {
                setLoading(false);
            });
    }, []);

    useEffect(() => {
        const controller = new AbortController();
        loadRepos(controller.signal);
        return () => controller.abort();
    }, [loadRepos]);

    async function handleSubmit(e) {
        e.preventDefault();
        setError("");
        setSubmitting(true);
        try {
            const res = await api.post("/api/repositories", form);
            setNewSecret(res.data.data.webhookSecret);
            setForm({ name: "", owner: "", githubUrl: "", defaultBranch: "main" });
            setShowForm(false);
            await loadRepos();
        } catch (err) {
            setError(err.response?.data?.message || "Failed to register repository.");
        } finally {
            setSubmitting(false);
        }
    }

    async function handleDelete(repoId) {
        if (!window.confirm("Are you sure you want to delete this repository registration?")) return;
        try {
            await api.delete(`/api/repositories/${repoId}`);
            await loadRepos();
        } catch (err) {
            setError(err.response?.data?.message || "Failed to delete repository.");
        }
    }

    function openPolicyModal(repo) {
        setSelectedRepoForPolicy(repo);
        setPolicyForm({
            policyConfig: {
                blockCritical: repo.policyConfig?.blockCritical ?? true,
                blockHigh: repo.policyConfig?.blockHigh ?? true,
                blockSecrets: repo.policyConfig?.blockSecrets ?? true,
                failOnCvssThreshold: repo.policyConfig?.failOnCvssThreshold ?? 8.0,
                maxAllowedHigh: repo.policyConfig?.maxAllowedHigh ?? 0,
                maxAllowedMedium: repo.policyConfig?.maxAllowedMedium ?? 5
            },
            scanConfig: {
                enableSemgrep: repo.scanConfig?.enableSemgrep ?? true,
                enableGitleaks: repo.scanConfig?.enableGitleaks ?? true,
                enableTrivy: repo.scanConfig?.enableTrivy ?? true,
                enableContainer: repo.scanConfig?.enableContainer ?? true,
                enableIac: repo.scanConfig?.enableIac ?? true,
                enableCicd: repo.scanConfig?.enableCicd ?? true
            }
        });
    }

    async function handleSavePolicy(e) {
        e.preventDefault();
        if (!selectedRepoForPolicy) return;
        setSavingPolicy(true);
        try {
            await api.patch(`/api/repositories/${selectedRepoForPolicy._id}`, policyForm);
            setSelectedRepoForPolicy(null);
            await loadRepos();
        } catch (err) {
            alert(err.response?.data?.message || "Failed to save security policy.");
        } finally {
            setSavingPolicy(false);
        }
    }

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
                        <span>📦</span> Registered Repositories & Security Policies
                    </h1>
                    <p className="text-xs text-slate-400 mt-1">
                        Configure security gates, CVSS failure thresholds, and scanning engines per repository.
                    </p>
                </div>
                <button
                    onClick={() => {
                        setShowForm((v) => !v);
                        setError("");
                    }}
                    className="btn-primary text-xs flex items-center gap-1.5"
                >
                    <span>{showForm ? "✕" : "➕"}</span>
                    <span>{showForm ? "Cancel" : "Register Repository"}</span>
                </button>
            </div>

            {newSecret && (
                <div className="bg-amber-950/40 border border-amber-600/50 rounded-xl p-5 shadow-lg">
                    <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-bold uppercase tracking-wider text-amber-300 flex items-center gap-2">
                            <span>🔑</span> Webhook Secret Generated
                        </span>
                        <button
                            onClick={() => setNewSecret(null)}
                            className="text-xs text-slate-400 hover:text-white"
                        >
                            ✕ Dismiss
                        </button>
                    </div>
                    <p className="text-xs text-slate-300 mb-2">
                        Save this secret now in your GitHub Webhook settings. It is hashed on the server and will not be displayed again:
                    </p>
                    <code className="text-xs font-mono bg-slate-900 px-3 py-1.5 rounded border border-slate-700 block break-all text-amber-400 select-all">
                        {newSecret}
                    </code>
                </div>
            )}

            {showForm && (
                <form
                    onSubmit={handleSubmit}
                    className="card p-6 grid grid-cols-1 sm:grid-cols-2 gap-4 gradient-border"
                >
                    <h3 className="col-span-1 sm:col-span-2 text-sm font-bold text-white border-b border-slate-800 pb-2">
                        Register New GitHub Repository
                    </h3>
                    {error && <p className="col-span-1 sm:col-span-2 text-red-400 text-xs">{error}</p>}
                    <div>
                        <label className="block text-xs font-medium text-slate-400 mb-1">Repository Name</label>
                        <input
                            required
                            placeholder="e.g. backend-api"
                            value={form.name}
                            onChange={(e) => setForm({ ...form, name: e.target.value })}
                            className="input-field text-xs"
                        />
                    </div>
                    <div>
                        <label className="block text-xs font-medium text-slate-400 mb-1">Owner / Organization</label>
                        <input
                            required
                            placeholder="e.g. acme-corp"
                            value={form.owner}
                            onChange={(e) => setForm({ ...form, owner: e.target.value })}
                            className="input-field text-xs"
                        />
                    </div>
                    <div className="col-span-1 sm:col-span-2">
                        <label className="block text-xs font-medium text-slate-400 mb-1">GitHub URL</label>
                        <input
                            required
                            type="url"
                            placeholder="https://github.com/org/repo"
                            value={form.githubUrl}
                            onChange={(e) => setForm({ ...form, githubUrl: e.target.value })}
                            className="input-field text-xs"
                        />
                    </div>
                    <div>
                        <label className="block text-xs font-medium text-slate-400 mb-1">Default Branch</label>
                        <input
                            value={form.defaultBranch}
                            onChange={(e) => setForm({ ...form, defaultBranch: e.target.value })}
                            className="input-field text-xs"
                        />
                    </div>
                    <div className="col-span-1 sm:col-span-2 flex justify-end gap-2 mt-2">
                        <button
                            type="button"
                            onClick={() => setShowForm(false)}
                            className="btn-ghost text-xs"
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            disabled={submitting}
                            className="btn-primary text-xs"
                        >
                            {submitting ? "Registering..." : "Register Repository"}
                        </button>
                    </div>
                </form>
            )}

            {/* Policy & Gate Configuration Modal */}
            {selectedRepoForPolicy && policyForm && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                    <div className="card w-full max-w-2xl p-6 bg-slate-900 border-slate-700 shadow-2xl max-h-[90vh] overflow-y-auto space-y-6">
                        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                            <div>
                                <h3 className="text-base font-bold text-white flex items-center gap-2">
                                    <span>⚙️</span> Configurable Security Gates & Policies
                                </h3>
                                <p className="text-xs text-slate-400 font-mono mt-0.5">
                                    {selectedRepoForPolicy.owner}/{selectedRepoForPolicy.name}
                                </p>
                            </div>
                            <button
                                onClick={() => setSelectedRepoForPolicy(null)}
                                className="text-slate-400 hover:text-white text-lg"
                            >
                                ✕
                            </button>
                        </div>

                        <form onSubmit={handleSavePolicy} className="space-y-6">
                            {/* Security Gates Section */}
                            <div className="space-y-3">
                                <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-300 border-b border-slate-800/80 pb-1.5 flex items-center gap-2">
                                    <span>🚦</span> Security Gate Enforcement Rules
                                </h4>

                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                                    {/* Gate 1: Fail on Critical */}
                                    <label className="flex items-center justify-between p-3 rounded-lg border border-slate-800 bg-slate-950/60 cursor-pointer hover:border-slate-700">
                                        <div>
                                            <span className="font-semibold text-slate-200 block">FAIL if Critical &gt; 0</span>
                                            <span className="text-[11px] text-slate-400">Block PR on any critical flaw</span>
                                        </div>
                                        <input
                                            type="checkbox"
                                            checked={policyForm.policyConfig.blockCritical}
                                            onChange={(e) => setPolicyForm({
                                                ...policyForm,
                                                policyConfig: { ...policyForm.policyConfig, blockCritical: e.target.checked }
                                            })}
                                            className="w-4 h-4 rounded text-blue-600 focus:ring-blue-500"
                                        />
                                    </label>

                                    {/* Gate 2: Fail on High */}
                                    <label className="flex items-center justify-between p-3 rounded-lg border border-slate-800 bg-slate-950/60 cursor-pointer hover:border-slate-700">
                                        <div>
                                            <span className="font-semibold text-slate-200 block">FAIL if High &gt; 0</span>
                                            <span className="text-[11px] text-slate-400">Block PR on high severity flaws</span>
                                        </div>
                                        <input
                                            type="checkbox"
                                            checked={policyForm.policyConfig.blockHigh}
                                            onChange={(e) => setPolicyForm({
                                                ...policyForm,
                                                policyConfig: { ...policyForm.policyConfig, blockHigh: e.target.checked }
                                            })}
                                            className="w-4 h-4 rounded text-blue-600 focus:ring-blue-500"
                                        />
                                    </label>

                                    {/* Gate 3: Fail on Secrets */}
                                    <label className="flex items-center justify-between p-3 rounded-lg border border-slate-800 bg-slate-950/60 cursor-pointer hover:border-slate-700">
                                        <div>
                                            <span className="font-semibold text-slate-200 block">FAIL if Secrets &gt; 0</span>
                                            <span className="text-[11px] text-slate-400">Zero-tolerance for exposed credentials</span>
                                        </div>
                                        <input
                                            type="checkbox"
                                            checked={policyForm.policyConfig.blockSecrets}
                                            onChange={(e) => setPolicyForm({
                                                ...policyForm,
                                                policyConfig: { ...policyForm.policyConfig, blockSecrets: e.target.checked }
                                            })}
                                            className="w-4 h-4 rounded text-rose-600 focus:ring-rose-500"
                                        />
                                    </label>

                                    {/* Gate 4: CVSS Threshold */}
                                    <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/60 flex flex-col justify-between">
                                        <div>
                                            <span className="font-semibold text-slate-200 block">FAIL if CVSS &gt;= Threshold</span>
                                            <span className="text-[11px] text-slate-400">Base score limit (0 to disable)</span>
                                        </div>
                                        <div className="flex items-center gap-2 mt-2">
                                            <input
                                                type="number"
                                                step="0.1"
                                                min="0"
                                                max="10"
                                                value={policyForm.policyConfig.failOnCvssThreshold}
                                                onChange={(e) => setPolicyForm({
                                                    ...policyForm,
                                                    policyConfig: { ...policyForm.policyConfig, failOnCvssThreshold: parseFloat(e.target.value) || 0 }
                                                })}
                                                className="input-field text-xs w-24 py-1"
                                            />
                                            <span className="text-[11px] text-slate-500 font-mono">/ 10.0 (e.g. 8.0)</span>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* Scan Engine Toggles */}
                            <div className="space-y-3">
                                <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-300 border-b border-slate-800/80 pb-1.5 flex items-center gap-2">
                                    <span>🔬</span> Active Security Scan Engines
                                </h4>

                                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 text-xs">
                                    <label className="flex items-center gap-2 p-2.5 rounded-lg border border-slate-800 bg-slate-950/40 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            checked={policyForm.scanConfig.enableSemgrep}
                                            onChange={(e) => setPolicyForm({
                                                ...policyForm,
                                                scanConfig: { ...policyForm.scanConfig, enableSemgrep: e.target.checked }
                                            })}
                                        />
                                        <span>🔬 SAST (Semgrep)</span>
                                    </label>

                                    <label className="flex items-center gap-2 p-2.5 rounded-lg border border-slate-800 bg-slate-950/40 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            checked={policyForm.scanConfig.enableGitleaks}
                                            onChange={(e) => setPolicyForm({
                                                ...policyForm,
                                                scanConfig: { ...policyForm.scanConfig, enableGitleaks: e.target.checked }
                                            })}
                                        />
                                        <span>🔑 Secrets (Gitleaks)</span>
                                    </label>

                                    <label className="flex items-center gap-2 p-2.5 rounded-lg border border-slate-800 bg-slate-950/40 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            checked={policyForm.scanConfig.enableTrivy}
                                            onChange={(e) => setPolicyForm({
                                                ...policyForm,
                                                scanConfig: { ...policyForm.scanConfig, enableTrivy: e.target.checked }
                                            })}
                                        />
                                        <span>📦 SCA (OSV / Trivy)</span>
                                    </label>

                                    <label className="flex items-center gap-2 p-2.5 rounded-lg border border-slate-800 bg-slate-950/40 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            checked={policyForm.scanConfig.enableContainer}
                                            onChange={(e) => setPolicyForm({
                                                ...policyForm,
                                                scanConfig: { ...policyForm.scanConfig, enableContainer: e.target.checked }
                                            })}
                                        />
                                        <span>🐳 Container (Docker)</span>
                                    </label>

                                    <label className="flex items-center gap-2 p-2.5 rounded-lg border border-slate-800 bg-slate-950/40 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            checked={policyForm.scanConfig.enableIac}
                                            onChange={(e) => setPolicyForm({
                                                ...policyForm,
                                                scanConfig: { ...policyForm.scanConfig, enableIac: e.target.checked }
                                            })}
                                        />
                                        <span>☁️ IaC (Terraform/K8s)</span>
                                    </label>

                                    <label className="flex items-center gap-2 p-2.5 rounded-lg border border-slate-800 bg-slate-950/40 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            checked={policyForm.scanConfig.enableCicd}
                                            onChange={(e) => setPolicyForm({
                                                ...policyForm,
                                                scanConfig: { ...policyForm.scanConfig, enableCicd: e.target.checked }
                                            })}
                                        />
                                        <span>🤖 CI/CD (Workflows)</span>
                                    </label>
                                </div>
                            </div>

                            <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
                                <button
                                    type="button"
                                    onClick={() => setSelectedRepoForPolicy(null)}
                                    className="btn-ghost text-xs"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    disabled={savingPolicy}
                                    className="btn-primary text-xs"
                                >
                                    {savingPolicy ? "Saving Policies..." : "Save Security Policies"}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* Repositories List */}
            {loading ? (
                <div className="space-y-3 animate-pulse">
                    {[...Array(3)].map((_, i) => (
                        <div key={i} className="card p-4 h-20 bg-slate-800/40" />
                    ))}
                </div>
            ) : repos.length === 0 ? (
                <div className="card p-12 text-center">
                    <p className="text-sm font-medium text-slate-300">No repositories registered yet.</p>
                    <p className="text-xs text-slate-500 mt-1">Register a repository above to configure scanning and security gates.</p>
                </div>
            ) : (
                <div className="space-y-3">
                    {repos.map((repo) => (
                        <div key={repo._id} className="card p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                            <div>
                                <div className="flex items-center gap-2 flex-wrap">
                                    <span className="font-semibold text-slate-100 text-sm">
                                        {repo.owner}/{repo.name}
                                    </span>
                                    <span className="text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700 px-2 py-0.5 rounded">
                                        Branch: {repo.defaultBranch}
                                    </span>
                                    {repo.policyConfig?.blockSecrets && (
                                        <span className="text-[10px] font-mono bg-rose-950/60 text-rose-300 border border-rose-800/40 px-1.5 py-0.5 rounded">
                                            Block Secrets
                                        </span>
                                    )}
                                    {repo.policyConfig?.failOnCvssThreshold > 0 && (
                                        <span className="text-[10px] font-mono bg-amber-950/60 text-amber-300 border border-amber-800/40 px-1.5 py-0.5 rounded">
                                            CVSS &ge; {repo.policyConfig.failOnCvssThreshold}
                                        </span>
                                    )}
                                </div>
                                <p className="text-xs text-slate-400 font-mono mt-1">{repo.githubUrl}</p>
                            </div>
                            <div className="flex items-center gap-3">
                                <button
                                    onClick={() => openPolicyModal(repo)}
                                    className="btn-secondary text-xs flex items-center gap-1.5"
                                >
                                    <span>⚙️</span>
                                    <span>Policies &amp; Gates</span>
                                </button>
                                <button
                                    onClick={() => handleDelete(repo._id)}
                                    className="text-xs text-red-400 hover:text-red-300 hover:underline px-2 py-1"
                                >
                                    Delete
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

export default Repositories;