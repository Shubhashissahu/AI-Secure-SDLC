import { Schema, model, Document, Types } from "mongoose";

export type ScanStatus = "pending" | "scanning" | "ai_review" | "completed" | "failed";
export type GateResult = "pass" | "fail" | "pending";

export interface IScan extends Document {
  repositoryId: Types.ObjectId;
  prNumber: number;
  commitSha: string;
  status: ScanStatus;
  scannerVersion: string;
  triggeredBy: string;
  startedAt: Date;
  completedAt?: Date;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  rescanSummary?: {
    newFindings: number;
    resolvedFindings: number;
    unchangedFindings: number;
  };
  gateResult: GateResult;
}

const scanSchema = new Schema<IScan>(
  {
    repositoryId: { type: Schema.Types.ObjectId, ref: "Repository", required: true, index: true },
    prNumber: { type: Number, required: true },
    commitSha: { type: String, required: true },
    status: {
      type: String,
      enum: ["pending", "scanning", "ai_review", "completed", "failed"],
      default: "pending"
    },
    scannerVersion: { type: String, default: "1.0.0" },
    triggeredBy: { type: String, required: true },
    startedAt: { type: Date, default: Date.now },
    completedAt: { type: Date },
    summary: {
      critical: { type: Number, default: 0 },
      high: { type: Number, default: 0 },
      medium: { type: Number, default: 0 },
      low: { type: Number, default: 0 },
      total: { type: Number, default: 0 }
    },
    rescanSummary: {
      newFindings: { type: Number, default: 0 },
      resolvedFindings: { type: Number, default: 0 },
      unchangedFindings: { type: Number, default: 0 }
    },
    gateResult: {
      type: String,
      enum: ["pass", "fail", "pending"],
      default: "pending"
    }
  },
  { timestamps: true }
);


// A CI job polling for status on the same PR/commit is the hottest read path.
scanSchema.index({ repositoryId: 1, prNumber: 1, commitSha: 1 });

export default model<IScan>("Scan", scanSchema);