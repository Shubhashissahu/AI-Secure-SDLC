import mongoose from "mongoose";
import dotenv from "dotenv";
import path from "path";

dotenv.config({ path: path.join(__dirname, "../../.env") });

import Finding from "../models/Finding";
import Scan from "../models/Scan";
import Repository from "../models/Repository";
import AIReview from "../models/AIReview";
import ScanJob from "../models/ScanJob";

async function clearDatabase(): Promise<void> {
  const confirmFlag = process.argv.includes("--confirm");

  if (!confirmFlag) {
    console.error(
      "[db:reset] ⚠️  This will permanently delete ALL data from the database.\n" +
      "[db:reset] Run with --confirm flag to proceed:\n" +
      "[db:reset]   npm run db:reset -- --confirm"
    );
    process.exit(1);
  }

  const uri = process.env.MONGO_URI || "mongodb://localhost:27017/ai_secure_sdlc";
  if (mongoose.connection.readyState === 0) {
    await mongoose.connect(uri);
  }

  console.log("[db:reset] Connected to MongoDB. Counting existing documents...\n");

  const beforeCounts = {
    findings: await Finding.countDocuments(),
    scans: await Scan.countDocuments(),
    repositories: await Repository.countDocuments(),
    aiReviews: await AIReview.countDocuments(),
    scanJobs: await ScanJob.countDocuments()
  };

  console.log("[db:reset] Before reset:");
  console.log(`  Findings:     ${beforeCounts.findings}`);
  console.log(`  Scans:        ${beforeCounts.scans}`);
  console.log(`  Repositories: ${beforeCounts.repositories}`);
  console.log(`  AI Reviews:   ${beforeCounts.aiReviews}`);
  console.log(`  Scan Jobs:    ${beforeCounts.scanJobs}`);
  console.log("");

  await Finding.deleteMany({});
  await Scan.deleteMany({});
  await Repository.deleteMany({});
  await AIReview.deleteMany({});
  await ScanJob.deleteMany({});

  const afterCounts = {
    findings: await Finding.countDocuments(),
    scans: await Scan.countDocuments(),
    repositories: await Repository.countDocuments(),
    aiReviews: await AIReview.countDocuments(),
    scanJobs: await ScanJob.countDocuments()
  };

  console.log("[db:reset] After reset:");
  console.log(`  Findings:     ${afterCounts.findings}`);
  console.log(`  Scans:        ${afterCounts.scans}`);
  console.log(`  Repositories: ${afterCounts.repositories}`);
  console.log(`  AI Reviews:   ${afterCounts.aiReviews}`);
  console.log(`  Scan Jobs:    ${afterCounts.scanJobs}`);
  console.log("");
  console.log("[db:reset] ✅ Database reset complete. All collections are empty.");
}

clearDatabase()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error("[db:reset] ❌ Failed:", err);
    process.exit(1);
  });
