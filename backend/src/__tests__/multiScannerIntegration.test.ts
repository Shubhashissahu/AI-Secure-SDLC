import path from "path";
import { SastScanner } from "../services/scanners/sastScannerService";
import { SecretScanner } from "../services/scanners/secretScannerService";
import { AiSecurityScanner } from "../services/scanners/aiSecurityScannerService";

describe("Multi-Scanner Integration Tests", () => {
  jest.setTimeout(30000);
  const fixturePath = path.resolve(__dirname, "fixtures/vulnerable-repo");

  it("1. SAST Scanner: Detects SQL Injection in Java and maps to CWE-89 with HIGH severity", async () => {
    const sastScanner = new SastScanner();
    const result = await sastScanner.scan(fixturePath);

    expect(result.status).toBe("success");
    const sqlFinding = result.findings.find(
      (f) => f.file.includes("SQLInjection.java") && f.cwe === "CWE-89"
    );

    expect(sqlFinding).toBeDefined();
    expect(sqlFinding?.severity).toBe("high");
    expect(sqlFinding?.category).toBe("SAST");
  });

  it("2. SAST Scanner: Detects Command Injection in Java and maps to CWE-78 with HIGH severity", async () => {
    const sastScanner = new SastScanner();
    const result = await sastScanner.scan(fixturePath);

    expect(result.status).toBe("success");
    const cmdFinding = result.findings.find(
      (f) => f.file.includes("CommandInjection.java") && f.cwe === "CWE-78"
    );

    expect(cmdFinding).toBeDefined();
    expect(cmdFinding?.severity).toBe("high");
    expect(cmdFinding?.category).toBe("SAST");
  });

  it("3. SAST Scanner: Detects XSS in Node.js and maps to CWE-79 with HIGH severity", async () => {
    const sastScanner = new SastScanner();
    const result = await sastScanner.scan(fixturePath);

    expect(result.status).toBe("success");
    const xssFinding = result.findings.find(
      (f) => f.file.includes("xss.js") && f.cwe === "CWE-79"
    );

    expect(xssFinding).toBeDefined();
    expect(xssFinding?.severity).toBe("high");
    expect(xssFinding?.category).toBe("SAST");
  });

  it("4. SAST Scanner: Detects Insecure Authentication in Node.js and maps to CWE-287", async () => {
    const sastScanner = new SastScanner();
    const result = await sastScanner.scan(fixturePath);

    expect(result.status).toBe("success");
    const authFinding = result.findings.find(
      (f) => f.file.includes("insecure-auth.js") && f.cwe === "CWE-287"
    );

    expect(authFinding).toBeDefined();
    expect(authFinding?.severity).toBe("high");
  });

  it("5. Secret Scanner: Detects Hardcoded Secrets in Java and maps to CWE-798 with CRITICAL severity", async () => {
    const secretScanner = new SecretScanner();
    const result = await secretScanner.scan(fixturePath);

    expect(result.status).toBe("success");
    const secretFinding = result.findings.find(
      (f) => f.file.includes("HardcodedSecret.java")
    );

    expect(secretFinding).toBeDefined();
    expect(secretFinding?.category).toBe("SECRETS");
    expect(secretFinding?.cwe).toBe("CWE-798");
  });

  it("6. AI Security Scanner: Detects Prompt Injection in Python and maps to CWE-20 / OWASP-LLM01", async () => {
    const aiScanner = new AiSecurityScanner();
    const result = await aiScanner.scan(fixturePath);

    expect(result.status).toBe("success");
    const promptInjection = result.findings.find(
      (f) => f.file.includes("prompt_injection.py") && (f.ruleId === "prompt-injection" || f.ruleId === "ai-prompt-injection-direct")
    );

    expect(promptInjection).toBeDefined();
    expect(promptInjection?.category).toBe("AI_SECURITY");
    expect(promptInjection?.severity.toLowerCase()).toBe("high");
    expect(promptInjection?.cwe).toBe("CWE-20");
  });

  it("7. AI Security Scanner: Detects Sensitive Data Exposure in LLM Prompts (data_leak.py)", async () => {
    const aiScanner = new AiSecurityScanner();
    const result = await aiScanner.scan(fixturePath);

    expect(result.status).toBe("success");
    const dataLeak = result.findings.find(
      (f) => f.file.includes("data_leak.py") && (f.ruleId === "data-leakage" || f.ruleId === "ai-sensitive-data-in-prompt")
    );

    expect(dataLeak).toBeDefined();
    expect(dataLeak?.category).toBe("AI_SECURITY");
    expect(["critical", "high"]).toContain(dataLeak?.severity.toLowerCase());
    expect(dataLeak?.cwe).toBe("CWE-200");
  });
});
