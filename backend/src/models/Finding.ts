import { Schema, model, Document, Types } from "mongoose";

export type FindingCategory = "SAST" | "SCA" | "SECRETS" | "AI_SECURITY" | "CONTAINER" | "IAC" | "CI_CD";
export type FindingTool =
  | "semgrep"
  | "gitleaks"
  | "trivy"
  | "codeql"
  | "dependency-check"
  | "osv"
  | "secret-scanner"
  | "sast-scanner"
  | "ai-security-scanner"
  | "container-scanner"
  | "iac-scanner"
  | "trivy-config"
  | "cicd-scanner";
export type FindingSeverity = "critical" | "high" | "medium" | "low";
export type FindingStatus =
  | "OPEN"
  | "CONFIRMED"
  | "LIKELY"
  | "NEEDS_REVIEW"
  | "FALSE_POSITIVE"
  | "REMEDIATED"
  | "RESOLVED"
  | "DISCOVERED"
  | "AI_REVIEWING"
  | "IGNORED"
  | "open"
  | "false_positive"
  | "confirmed"
  | "remediated";

export interface IFinding extends Document {
  scanId: Types.ObjectId;
  repositoryId: Types.ObjectId;
  commitSha: string;
  fingerprint: string;
  category: FindingCategory;
  tool: FindingTool;
  file: string;
  line: number;
  ruleId: string;
  cwe?: string;
  title?: string;
  description?: string;
  codeSnippet: string;
  secretRef?: string | null;
  secretType?: string;
  isMasked?: boolean;

  // SCA fields
  package?: string;
  installedVersion?: string;
  fixedVersion?: string;
  cve?: string;
  cvss?: number;
  scaRemediation?: string;

  // Container & IaC fields
  resourceName?: string;
  resourceType?: string;
  containerImage?: string;
  iacPlatform?: "docker" | "docker-compose" | "terraform" | "kubernetes" | "generic";
  complianceStandard?: string;

  // CI/CD fields
  workflowName?: string;
  actionName?: string;

  severity: FindingSeverity;
  status: FindingStatus;
  occurrences: number;
  firstSeenAt: Date;
  lastSeenAt: Date;
  resolvedCommitSha?: string;
  resolvedAt?: Date;

  ai?: {
    isRealVulnerability: boolean;
    confidence: number;
    confidenceLevel?: "manual_review" | "warning" | "allow_automated_decision";
    reason?: string;
    attackScenario: string;
    cwe: string;
    owasp: string;
    exploitability: "low" | "medium" | "high";
    recommendation?: string;
    secureFix?: string;
    remediation: { patch: string; explanation: string };
    reviewFailed: boolean;
  };
  risk?: {
    score: number;
    severityWeight: number;
    exploitabilityWeight: number;
    businessImpactWeight: number;
    exposureWeight: number;
    assetCriticalityWeight?: number;
    authRequiredWeight?: number;
    exploitAvailabilityWeight?: number;
    reason?: string;
    decision?: "BLOCK" | "REVIEW" | "WARN" | "IGNORE";
  };
}

const findingSchema = new Schema<IFinding>(
  {
    scanId: { type: Schema.Types.ObjectId, ref: "Scan", required: true, index: true },
    repositoryId: { type: Schema.Types.ObjectId, ref: "Repository", required: true, index: true },
    commitSha: { type: String, required: true, index: true },
    fingerprint: { type: String, required: true, unique: true, index: true },
    category: {
      type: String,
      enum: ["SAST", "SCA", "SECRETS", "AI_SECURITY", "CONTAINER", "IAC", "CI_CD"],
      default: "SAST",
      index: true
    },
    tool: { type: String, required: true, index: true },
    file: { type: String, required: true },
    line: { type: Number, required: true },
    ruleId: { type: String, required: true },
    cwe: { type: String, default: "CWE-200" },
    title: { type: String },
    description: { type: String },
    codeSnippet: { type: String, required: true, maxlength: 4000 },
    secretRef: { type: String, default: null },
    secretType: { type: String },
    isMasked: { type: Boolean, default: false },

    // SCA fields
    package: { type: String },
    installedVersion: { type: String },
    fixedVersion: { type: String },
    cve: { type: String },
    cvss: { type: Number },
    scaRemediation: { type: String },

    // Container & IaC fields
    resourceName: { type: String },
    resourceType: { type: String },
    containerImage: { type: String },
    iacPlatform: { type: String, enum: ["docker", "docker-compose", "terraform", "kubernetes", "generic"] },
    complianceStandard: { type: String },

    // CI/CD fields
    workflowName: { type: String },
    actionName: { type: String },

    severity: { type: String, enum: ["critical", "high", "medium", "low"], required: true, index: true },
    status: {
      type: String,
      enum: [
        "OPEN",
        "CONFIRMED",
        "LIKELY",
        "NEEDS_REVIEW",
        "FALSE_POSITIVE",
        "REMEDIATED",
        "RESOLVED",
        "DISCOVERED",
        "AI_REVIEWING",
        "IGNORED",
        "open",
        "false_positive",
        "confirmed",
        "remediated"
      ],
      default: "OPEN",
      index: true
    },
    occurrences: { type: Number, default: 1 },
    firstSeenAt: { type: Date, default: Date.now },
    lastSeenAt: { type: Date, default: Date.now },
    resolvedCommitSha: { type: String },
    resolvedAt: { type: Date },

    ai: {
      isRealVulnerability: { type: Boolean },
      confidence: { type: Number, min: 0, max: 100 },
      confidenceLevel: {
        type: String,
        enum: ["manual_review", "warning", "allow_automated_decision"]
      },
      reason: { type: String },
      attackScenario: { type: String },
      cwe: { type: String },
      owasp: { type: String },
      exploitability: { type: String, enum: ["low", "medium", "high"] },
      recommendation: { type: String },
      secureFix: { type: String },
      remediation: {
        patch: { type: String },
        explanation: { type: String }
      },
      reviewFailed: { type: Boolean, default: false }
    },
    risk: {
      score: { type: Number, min: 0, max: 100 },
      severityWeight: { type: Number, min: 0, max: 40 },
      exploitabilityWeight: { type: Number, min: 0, max: 30 },
      businessImpactWeight: { type: Number, min: 0, max: 20 },
      exposureWeight: { type: Number, min: 0, max: 10 },
      assetCriticalityWeight: { type: Number },
      authRequiredWeight: { type: Number },
      exploitAvailabilityWeight: { type: Number },
      reason: { type: String },
      decision: { type: String, enum: ["BLOCK", "REVIEW", "WARN", "IGNORE"] }
    }
  },
  {
    timestamps: true,
    toJSON: {
      virtuals: true,
      transform: function (_doc, ret: any) {
        ret.rule = ret.ruleId;
        ret.scanner = ret.tool;
        ret.confidence = ret.ai?.confidence !== undefined ? String(ret.ai.confidence) : "90";
        return ret;
      }
    },
    toObject: {
      virtuals: true,
      transform: function (_doc, ret: any) {
        ret.rule = ret.ruleId;
        ret.scanner = ret.tool;
        ret.confidence = ret.ai?.confidence !== undefined ? String(ret.ai.confidence) : "90";
        return ret;
      }
    }
  }
);

findingSchema.virtual("rule").get(function () {
  return this.ruleId;
});

findingSchema.virtual("scanner").get(function () {
  return this.tool;
});

findingSchema.virtual("confidence").get(function () {
  return this.ai?.confidence !== undefined ? String(this.ai.confidence) : "90";
});

findingSchema.index({ scanId: 1, severity: 1 });
findingSchema.index({ repositoryId: 1, status: 1 });
findingSchema.index({ repositoryId: 1, severity: 1 });

export default model<IFinding>("Finding", findingSchema);