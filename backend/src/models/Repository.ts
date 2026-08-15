import { Schema, model, Document } from "mongoose";

export interface IRepository extends Document {
  name: string;
  owner: string;
  githubUrl: string;
  defaultBranch: string;
  webhookId?: string;
  webhookSecret: string;
  isActive: boolean;
  scanConfig: {
    enableSemgrep: boolean;
    enableGitleaks: boolean;
    enableTrivy: boolean;
    enableContainer: boolean;
    enableIac: boolean;
    enableCicd: boolean;
  };
  policyConfig: {
    blockCritical: boolean;
    blockHigh: boolean;
    blockSecrets: boolean;
    failOnCvssThreshold: number;
    maxAllowedHigh: number;
    maxAllowedMedium: number;
  };
}

const repositorySchema = new Schema<IRepository>(
  {
    name: { type: String, required: true },
    owner: { type: String, required: true },
    githubUrl: { type: String, required: true, unique: true },
    defaultBranch: { type: String, default: "main" },
    webhookId: { type: String },
    webhookSecret: { type: String, required: true },
    isActive: { type: Boolean, default: true },
    scanConfig: {
      enableSemgrep: { type: Boolean, default: true },
      enableGitleaks: { type: Boolean, default: true },
      enableTrivy: { type: Boolean, default: true },
      enableContainer: { type: Boolean, default: true },
      enableIac: { type: Boolean, default: true },
      enableCicd: { type: Boolean, default: true }
    },
    policyConfig: {
      blockCritical: { type: Boolean, default: true },
      blockHigh: { type: Boolean, default: true },
      blockSecrets: { type: Boolean, default: true },
      failOnCvssThreshold: { type: Number, default: 8.0 },
      maxAllowedHigh: { type: Number, default: 0 },
      maxAllowedMedium: { type: Number, default: 5 }
    }
  },
  { timestamps: true }
);

// Support looking up repos by owner/name
repositorySchema.index({ owner: 1, name: 1 });

export default model<IRepository>("Repository", repositorySchema);
