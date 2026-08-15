import { Schema, model, Document, Types } from "mongoose";

export type JobStatus = "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";

export interface IScanJob extends Document {
  scanId: Types.ObjectId;
  status: JobStatus;
  startedAt?: Date;
  completedAt?: Date;
  error?: string;
  attemptCount: number;
}

const scanJobSchema = new Schema<IScanJob>(
  {
    scanId: { type: Schema.Types.ObjectId, ref: "Scan", required: true, index: true },
    status: {
      type: String,
      enum: ["QUEUED", "RUNNING", "COMPLETED", "FAILED"],
      default: "QUEUED",
      index: true
    },
    startedAt: { type: Date },
    completedAt: { type: Date },
    error: { type: String },
    attemptCount: { type: Number, default: 0 }
  },
  { timestamps: true }
);

export default model<IScanJob>("ScanJob", scanJobSchema);
