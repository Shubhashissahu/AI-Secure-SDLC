import { readFile } from "fs/promises";
import { existsSync } from "fs";
import path from "path";

const CONTEXT_LINES_BEFORE = 20;
const CONTEXT_LINES_AFTER = 20;
const MAX_CONTEXT_CHARS = 6000;

const EXTENSION_LANGUAGE_MAP: Record<string, string> = {
    ".ts": "TypeScript",
    ".tsx": "TypeScript (React)",
    ".js": "JavaScript",
    ".jsx": "JavaScript (React)",
    ".py": "Python",
    ".java": "Java",
    ".go": "Go",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#"
};

export interface CodeContext {
    language: string;
    surroundingCode: string;
    imports: string[];
}

function detectLanguage(filePath: string): string {
    return EXTENSION_LANGUAGE_MAP[path.extname(filePath)] || "Unknown";
}

/**
 * Very lightweight import/require detector — good enough to give the LLM a
 * sense of what a file depends on (e.g. whether it uses a raw DB driver vs.
 * an ORM) without needing a full AST parse for every language.
 */
function extractImports(fileContent: string): string[] {
    const importLines = fileContent
        .split("\n")
        .slice(0, 50) // imports are almost always near the top of the file
        .filter((line) => /^\s*(import|require|from|using|use)\b/.test(line));
    return importLines.slice(0, 20);
}

/**
 * Reads the target file and slices out a window of lines around the
 * reported finding, plus a best-effort import list, to give the AI reviewer
 * enough context to reason about the finding without sending the entire
 * file (which would blow past reasonable prompt sizes on large files).
 *
 * Returns `null` if the file cannot be found — callers should skip AI
 * review when context is null rather than reviewing with empty context.
 */
export async function extractCodeContext(
    repoPath: string,
    relativeFilePath: string,
    line: number
): Promise<CodeContext | null> {
    const absolutePath = path.isAbsolute(relativeFilePath) ? relativeFilePath : path.join(repoPath, relativeFilePath);

    // Guard against path traversal: the resolved path must stay inside repoPath.
    const resolved = path.resolve(absolutePath);
    if (!resolved.startsWith(path.resolve(repoPath))) {
        console.warn(`[contextExtractor] Path traversal blocked: ${relativeFilePath}`);
        return null;
    }

    // Explicit file existence check — return null so callers know the file is missing
    if (!existsSync(resolved)) {
        console.warn(`[contextExtractor] File not found: ${resolved}`);
        return null;
    }

    try {
        const content = await readFile(resolved, "utf-8");
        const lines = content.split("\n");

        const startIdx = Math.max(0, line - 1 - CONTEXT_LINES_BEFORE);
        const endIdx = Math.min(lines.length, line + CONTEXT_LINES_AFTER);

        const surroundingCode = lines
            .slice(startIdx, endIdx)
            .map((text, idx) => `${startIdx + idx + 1}: ${text}`)
            .join("\n")
            .slice(0, MAX_CONTEXT_CHARS);

        return {
            language: detectLanguage(relativeFilePath),
            surroundingCode,
            imports: extractImports(content)
        };
    } catch {
        console.warn(`[contextExtractor] Failed to read file: ${resolved}`);
        return null;
    }
}

