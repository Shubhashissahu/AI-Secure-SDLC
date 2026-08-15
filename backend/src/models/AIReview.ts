import { Schema, model, Document, Types } from "mongoose";

export interface IAIReview extends Document {
  findingId: Types.ObjectId;
  scanId: Types.ObjectId;
  aiModel: string;
  promptVersion: string;
  promptText: string;
  rawResponse: string;
  confidence: number;
  cwe?: string;
  owasp?: string;
  reviewFailed: boolean;
}

const aiReviewSchema = new Schema<IAIReview>(
  {
    findingId: { type: Schema.Types.ObjectId, ref: "Finding", required: true, index: true },
    scanId: { type: Schema.Types.ObjectId, ref: "Scan", required: true, index: true },
    aiModel: { type: String, required: true, default: "codellama:13b" },
    promptVersion: { type: String, required: true, default: "v1" },
    promptText: { type: String, required: true },
    rawResponse: { type: String, required: true },
    confidence: { type: Number, required: true, min: 0, max: 100 },
    cwe: { type: String },
    owasp: { type: String },
    reviewFailed: { type: Boolean, default: false }
  },
  { timestamps: true }
);

export default model<IAIReview>("AIReview", aiReviewSchema);
