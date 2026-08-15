import mongoose from "mongoose";

/**
 * Establishes the MongoDB connection.
 *
 * Security note: connection string must live in env vars only (see .env.example).
 * We fail fast and exit the process if the DB is unreachable at boot rather than
 * letting the API serve requests against a dead datastore.
 */
export async function connectDB(): Promise<void> {
  const uri = process.env.MONGO_URI;

  if (!uri) {
    throw new Error("MONGO_URI is not set. Check your .env file.");
  }

  mongoose.set("strictQuery", true);

  try {
    await mongoose.connect(uri);
    // eslint-disable-next-line no-console
    console.log("[db] MongoDB connected");
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error("[db] MongoDB connection failed:", err);
    process.exit(1);
  }

  mongoose.connection.on("disconnected", () => {
    // eslint-disable-next-line no-console
    console.warn("[db] MongoDB disconnected");
  });
}
