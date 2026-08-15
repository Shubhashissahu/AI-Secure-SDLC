import { useState } from "react";
import SeverityBadge from "./SeverityBadge";

/**
 * Individual finding card component showing key finding details,
 * AI review results, and remediation suggestions.
 */
function ScanResultsCard({ finding }) {
  const [expanded, setExpanded] = useState(false);

  const hasAIReview = finding.ai && Object.keys(finding.ai).length > 0;
  const hasRisk = finding.risk && Object.keys(finding.risk).length > 0;

  return (
    <div className="bg-white border border-gray-200 rounded-lg overflow-hidden hover:shadow-md transition">
      <div
        onClick={() => setExpanded(!expanded)}
        className="p-4 cursor-pointer hover:bg-slate-50"
      >
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <div className="flex items-center gap-3">
              <SeverityBadge severity={finding.severity} />
              <div className="flex-1">
                <h4 className="font-semibold text-gray-900">{finding.ruleId}</h4>
                <p className="text-sm text-gray-600">
                  {finding.file}:<span className="font-mono font-semibold">{finding.line}</span>
                </p>
              </div>
            </div>
            {hasAIReview && (
              <div className="mt-2 flex items-center gap-2">
                <span className="text-xs bg-blue-50 text-blue-700 px-2 py-1 rounded">
                  AI Confidence: {finding.ai.confidence}%
                </span>
                {finding.ai.isRealVulnerability && (
                  <span className="text-xs bg-red-50 text-red-700 px-2 py-1 rounded">
                    Real Vulnerability
                  </span>
                )}
              </div>
            )}
          </div>
          <button
            className="text-gray-400 hover:text-gray-600 ml-2"
            onClick={(e) => {
              e.stopPropagation();
              setExpanded(!expanded);
            }}
          >
            <span className="text-xl">{expanded ? "−" : "+"}</span>
          </button>
        </div>
      </div>

      {expanded && (
        <div className="border-t border-gray-200 p-4 bg-slate-50 space-y-4">
          {/* Code Snippet */}
          <div>
            <p className="text-xs font-medium text-gray-600 uppercase mb-2">Code Context</p>
            <pre className="bg-gray-900 text-gray-100 p-3 rounded text-xs overflow-x-auto">
              {finding.codeSnippet}
            </pre>
          </div>

          {/* AI Review */}
          {hasAIReview && (
            <div className="bg-white border border-blue-200 rounded p-4">
              <h5 className="font-semibold text-blue-900 mb-3">🤖 AI Security Review</h5>
              <div className="space-y-2 text-sm">
                <div>
                  <p className="text-gray-600">
                    <strong>Attack Scenario:</strong>
                  </p>
                  <p className="text-gray-700 mt-1">{finding.ai.attackScenario}</p>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <p className="text-gray-600">
                      <strong>CWE:</strong>
                    </p>
                    <p className="font-mono text-gray-700">{finding.ai.cwe}</p>
                  </div>
                  <div>
                    <p className="text-gray-600">
                      <strong>OWASP:</strong>
                    </p>
                    <p className="font-mono text-gray-700">{finding.ai.owasp}</p>
                  </div>
                </div>
                <div>
                  <p className="text-gray-600">
                    <strong>Remediation:</strong>
                  </p>
                  <pre className="bg-green-50 border border-green-200 p-2 rounded mt-1 text-xs overflow-x-auto">
                    {finding.ai.remediation.patch}
                  </pre>
                  <p className="text-gray-700 mt-2">{finding.ai.remediation.explanation}</p>
                </div>
              </div>
            </div>
          )}

          {/* Risk Score */}
          {hasRisk && (
            <div className="bg-white border border-orange-200 rounded p-4">
              <h5 className="font-semibold text-orange-900 mb-3">📊 Risk Assessment</h5>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                <div className="text-center">
                  <p className="text-xs text-gray-600 uppercase mb-1">Overall</p>
                  <p className="text-2xl font-bold text-orange-600">{finding.risk.score}</p>
                  <p className="text-xs text-gray-500">/ 100</p>
                </div>
                <div className="text-center">
                  <p className="text-xs text-gray-600 uppercase mb-1">Severity</p>
                  <p className="text-lg font-bold text-red-600">{finding.risk.severityWeight}</p>
                  <p className="text-xs text-gray-500">of 40</p>
                </div>
                <div className="text-center">
                  <p className="text-xs text-gray-600 uppercase mb-1">Exploit</p>
                  <p className="text-lg font-bold text-orange-600">
                    {finding.risk.exploitabilityWeight}
                  </p>
                  <p className="text-xs text-gray-500">of 30</p>
                </div>
                <div className="text-center">
                  <p className="text-xs text-gray-600 uppercase mb-1">Business</p>
                  <p className="text-lg font-bold text-yellow-600">
                    {finding.risk.businessImpactWeight}
                  </p>
                  <p className="text-xs text-gray-500">of 20</p>
                </div>
                <div className="text-center">
                  <p className="text-xs text-gray-600 uppercase mb-1">Exposure</p>
                  <p className="text-lg font-bold text-green-600">
                    {finding.risk.exposureWeight}
                  </p>
                  <p className="text-xs text-gray-500">of 10</p>
                </div>
              </div>
            </div>
          )}

          {/* Finding Details */}
          <div className="bg-white border border-gray-200 rounded p-4">
            <h5 className="font-semibold text-gray-900 mb-3">Details</h5>
            <div className="space-y-2 text-sm">
              <p>
                <strong>Tool:</strong>{" "}
                <span className="bg-gray-100 px-2 py-1 rounded text-xs font-mono">
                  {finding.tool}
                </span>
              </p>
              <p>
                <strong>Status:</strong>{" "}
                <span className={`px-2 py-1 rounded text-xs font-semibold ${
                  finding.status === "open" ? "bg-yellow-100 text-yellow-800" :
                  finding.status === "confirmed" ? "bg-red-100 text-red-800" :
                  finding.status === "false_positive" ? "bg-green-100 text-green-800" :
                  "bg-gray-100 text-gray-800"
                }`}>
                  {finding.status}
                </span>
              </p>
              {finding.secretRef && (
                <p>
                  <strong>Secret Ref:</strong>{" "}
                  <span className="font-mono text-xs text-gray-600">{finding.secretRef}</span>
                </p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default ScanResultsCard;
