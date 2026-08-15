import { Schema, model, Document } from "mongoose";
import bcrypt from "bcryptjs";

export type UserRole = "admin" | "developer" | "viewer" | "service";

export interface IUser extends Document {
    email: string;
    passwordHash: string;
    name: string;
    role: UserRole;
    comparePassword(candidate: string): Promise<boolean>;
}

const userSchema = new Schema<IUser>(
    {
        email: { type: String, required: true, unique: true, lowercase: true, trim: true },
        // Never store or return the plaintext password — select:false keeps it
        // out of default query results the same way Repository.webhookSecret is
        // handled.
        passwordHash: { type: String, required: true, select: false },
        name: { type: String, required: true },
        role: { type: String, enum: ["admin", "developer", "viewer", "service"], default: "developer" }
    },
    { timestamps: true }
);
userSchema.methods.comparePassword = async function (candidate: string): Promise<boolean> {
    return bcrypt.compare(candidate, this.passwordHash);
};

export default model<IUser>("User", userSchema);