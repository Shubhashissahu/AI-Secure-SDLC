/**
 * Universal Secret Masking Utility for AI Secure SDLC.
 * Ensures secrets are never exposed in UI, logs, reports, or database plaintext.
 */

// Common secret patterns for proactive masking in any text/code snippet/log
export const SECRET_MASK_PATTERNS: Array<{ regex: RegExp; name: string }> = [
  // 1. AWS Credentials
  { regex: /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g, name: "aws_access_key" },
  { regex: /(aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["']?)([A-Za-z0-9/+=]{40})(["']?)/gi, name: "aws_secret_key" },

  // 2. GitHub Tokens
  { regex: /gh[pousr]_[A-Za-z0-9_]{36,255}/g, name: "github_token" },
  { regex: /github_pat_[A-Za-z0-9_]{82}/g, name: "github_pat" },

  // 3. Private Keys (RSA, EC, DSA, OPENSSH, PGP)
  { regex: /-----BEGIN (?:[A-Z0-9_-]+\s)?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+\s)?PRIVATE KEY-----/g, name: "private_key" },
  { regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g, name: "pgp_private_key" },

  // 4. JWT Tokens
  { regex: /eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+/g, name: "jwt_token" },

  // 5. Database Connection Strings with Passwords
  { regex: /((?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|mssql):\/\/[^:\s'"]+:)([^@\s'"]+)(@[^\s'"]+)/gi, name: "db_uri" },
  { regex: /((?:db_password|database_password|dbpass|db_pass|password|pwd|db_secret)\s*[:=]\s*["'])([^"'\r\n]{3,})(["'])/gi, name: "db_password_assign" },

  // 6. Generic & Provider API Keys
  { regex: /(sk-[a-zA-Z0-9]{32,64})/g, name: "openai_key" },
  { regex: /(sk_live_[0-9a-zA-Z]{24,34})/g, name: "stripe_key" },
  { regex: /(AIza[0-9A-Za-z-_]{35})/g, name: "google_api_key" },
  { regex: /(xox[baprs]-[0-9a-zA-Z]{10,48})/g, name: "slack_token" },
  { regex: /((?:api[_-]?key|apikey|auth[_-]?token|secret[_-]?key|client[_-]?secret)\s*[:=]\s*["'])([A-Za-z0-9-_.~+/=]{8,})(["'])/gi, name: "api_key_assign" },

  // 7. Access Tokens & Bearer Headers
  { regex: /(Bearer\s+)([A-Za-z0-9-._~+/=]{20,})/gi, name: "bearer_token" },
  { regex: /((?:access[_-]?token|refresh[_-]?token|id[_-]?token|jwt[_-]?secret)\s*[:=]\s*["'])([A-Za-z0-9-_.~+/=]{8,})(["'])/gi, name: "access_token_assign" }
];

/**
 * Masks a secret string keeping the first 4 and last 3 characters visible if length > 12,
 * otherwise masks with standard asterisks.
 */
export function maskSecretValue(secret: string): string {
  if (!secret) return "";
  const trimmed = secret.trim();
  if (trimmed.length <= 8) {
    return "********";
  }
  if (trimmed.length <= 16) {
    return `${trimmed.slice(0, 2)}****${trimmed.slice(-2)}`;
  }
  return `${trimmed.slice(0, 4)}****************${trimmed.slice(-3)}`;
}

/**
 * Universal text scrubber: Scans any text (code snippet, log string, error message)
 * and replaces any matched sensitive secrets with masked equivalents.
 */
export function maskAllSecretsInText(text: string): string {
  if (!text || typeof text !== "string") return text;
  let sanitized = text;

  // Mask private key blocks specially
  sanitized = sanitized.replace(
    /-----BEGIN (?:[A-Z0-9_-]+\s)?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+\s)?PRIVATE KEY-----/g,
    "-----BEGIN PRIVATE KEY-----\n[MASKED PRIVATE KEY CONTENT]\n-----END PRIVATE KEY-----"
  );
  sanitized = sanitized.replace(
    /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g,
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\n[MASKED PGP PRIVATE KEY]\n-----END PGP PRIVATE KEY BLOCK-----"
  );

  // Mask database URIs
  sanitized = sanitized.replace(
    /((?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|mssql):\/\/[^:\s'"]+:)([^@\s'"]+)(@[^\s'"]+)/gi,
    (_match, prefix, password, suffix) => `${prefix}${maskSecretValue(password)}${suffix}`
  );

  // Mask key=value assignments (quoted or unquoted, with or without ENV / prefix)
  sanitized = sanitized.replace(
    /((?:ENV\s+|ARG\s+|-\s+)?(?:api[_-]?key|apikey|api[_-]?secret[_-]?key|auth[_-]?token|secret[_-]?key|client[_-]?secret|db_password|database_password|dbpass|db_pass|password|pwd|jwt_secret|access[_-]?token|refresh[_-]?token)\s*[:=]\s*["']?)([^"'\r\n\s]{3,})(["']?)/gi,
    (_match, prefix, value, suffix) => `${prefix}${maskSecretValue(value)}${suffix}`
  );

  // Mask AWS keys
  sanitized = sanitized.replace(/(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g, (key) => maskSecretValue(key));

  // Mask GitHub tokens
  sanitized = sanitized.replace(/gh[pousr]_[A-Za-z0-9_]{36,255}/g, (token) => maskSecretValue(token));
  sanitized = sanitized.replace(/github_pat_[A-Za-z0-9_]{82}/g, (token) => maskSecretValue(token));

  // Mask generic provider keys
  sanitized = sanitized.replace(/(?:sk-[a-zA-Z0-9]{32,64}|sk_live_[0-9a-zA-Z]{24,34}|AIza[0-9A-Za-z-_]{35}|xox[baprs]-[0-9a-zA-Z]{10,48})/g, (key) => maskSecretValue(key));

  // Mask JWT tokens
  sanitized = sanitized.replace(/eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+/g, (jwt) => {
    const parts = jwt.split(".");
    return `${parts[0]}.${parts[1].slice(0, 10)}...[MASKED_SIGNATURE]`;
  });

  return sanitized;
}

/**
 * Safe logger proxy that automatically strips secrets before logging.
 */
export const safeLog = {
  info: (...args: unknown[]) => {
    console.log(...args.map((a) => (typeof a === "string" ? maskAllSecretsInText(a) : a)));
  },
  warn: (...args: unknown[]) => {
    console.warn(...args.map((a) => (typeof a === "string" ? maskAllSecretsInText(a) : a)));
  },
  error: (...args: unknown[]) => {
    console.error(...args.map((a) => (typeof a === "string" ? maskAllSecretsInText(a) : a)));
  }
};
