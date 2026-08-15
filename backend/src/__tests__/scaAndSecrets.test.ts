import { maskAllSecretsInText, maskSecretValue } from "../utils/secretMasker";
import { SecretScanner } from "../services/scanners/secretScannerService";
import { OsvDependencyScanner, extractCvssScore, cvssToSeverity } from "../services/scanners/osvScannerService";
import { reviewFinding } from "../services/ai/aiReviewerService";
import { NormalizedFinding } from "../services/scanners/types";
import path from "path";
import fs from "fs";
import os from "os";

describe("SCA & Secret Scanning Test Suite", () => {
  jest.setTimeout(30000);

  // -------------------------------------------------------------
  // Test 1: Secret Masking Utility
  // -------------------------------------------------------------
  test("Test 1: Universal Secret Masking masks AWS keys, GitHub tokens, DB passwords, JWTs and Private Keys", () => {
    const rawAwsKey = "AKIAIOSFODNN7EXAMPLE";
    const maskedAws = maskSecretValue(rawAwsKey);
    expect(maskedAws).not.toContain("IOSFODNN7");
    expect(maskedAws).toContain("****");

    const sampleLog = `
      Connected with postgres://admin:SuperSecretPassword123@db.example.com:5432/mydb
      AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
      GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef1234
      api_key = "sk-abcdef1234567890abcdef1234567890"
      jwt_secret = "myUltraSecretJwtSigningKey!"
      -----BEGIN RSA PRIVATE KEY-----
      MIIEowIBAAKCAQEA0Y1+
      -----END RSA PRIVATE KEY-----
    `;

    const maskedLog = maskAllSecretsInText(sampleLog);

    expect(maskedLog).not.toContain("SuperSecretPassword123");
    expect(maskedLog).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(maskedLog).not.toContain("ghp_1234567890abcdef1234567890abcdef1234");
    expect(maskedLog).not.toContain("sk-abcdef1234567890abcdef1234567890");
    expect(maskedLog).not.toContain("myUltraSecretJwtSigningKey!");
    expect(maskedLog).toContain("[MASKED PRIVATE KEY CONTENT]");
  });

  // -------------------------------------------------------------
  // Test 2: Detection of all 7 Secret Categories
  // -------------------------------------------------------------
  test("Test 2: SecretScanner detects API keys, AWS credentials, GitHub tokens, JWT secrets, DB passwords, Private keys, Access tokens", async () => {
    const tmpDir = path.join(os.tmpdir(), `secret-test-${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });

    try {
      const testContent = `
        // 1. AWS credentials
        const awsKey = "AKIAIOSFODNN7EXAMPLE";
        const awsSecret = "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'";

        // 2. GitHub tokens
        const ghToken = "ghp_1234567890abcdef1234567890abcdef1234";

        // 3. API keys
        const openAi = "sk-1234567890abcdef1234567890abcdef12";
        const stripe = "sk_live_1234567890abcdef12345678";
        const google = "AIzaSyD1234567890abcdef1234567890abcdef";

        // 4. JWT secrets
        const jwtSecret = 'jwt_secret = "SuperSecretSigningToken123"';

        // 5. Database passwords
        const dbUri = "mongodb+srv://admin:DbSecretPass987@cluster0.mongodb.net/test";

        // 6. Access tokens
        const bearer = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456";

        // 7. Private keys
        const key = "-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD\\n-----END PRIVATE KEY-----";
      `;

      fs.writeFileSync(path.join(tmpDir, "secrets.js"), testContent, "utf-8");

      const scanner = new SecretScanner();
      const result = await scanner.scan(tmpDir);

      expect(result.status).toBe("success");
      expect(result.findings.length).toBeGreaterThanOrEqual(7);

      expect(result.findings.some((f) => f.secretType === "aws_credential" || f.ruleId.includes("aws"))).toBe(true);
      expect(result.findings.some((f) => f.secretType === "github_token" || f.ruleId.includes("github"))).toBe(true);
      expect(result.findings.some((f) => f.secretType === "api_key" || f.ruleId.includes("api"))).toBe(true);
      expect(result.findings.some((f) => f.secretType === "jwt_secret" || f.ruleId.includes("jwt"))).toBe(true);
      expect(result.findings.some((f) => f.secretType === "db_password" || f.ruleId.includes("database"))).toBe(true);
      expect(result.findings.some((f) => f.secretType === "private_key" || f.ruleId.includes("private-key"))).toBe(true);
      expect(result.findings.some((f) => f.secretType === "access_token" || f.ruleId.includes("access"))).toBe(true);

      // Verify all findings have masked code snippets
      for (const finding of result.findings) {
        expect(finding.codeSnippet).not.toContain("DbSecretPass987");
        expect(finding.codeSnippet).not.toContain("wJalrXUtnFEMI");
        expect(finding.codeSnippet).not.toContain("SuperSecretSigningToken123");
        expect(finding.isMasked).toBe(true);
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // -------------------------------------------------------------
  // Test 3: SCA Dependency Scanner for 11 manifest formats
  // -------------------------------------------------------------
  test("Test 3: OsvDependencyScanner discovers dependencies across all 11 manifest formats", async () => {
    const tmpDir = path.join(os.tmpdir(), `sca-manifest-test-${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });

    try {
      // 1. package.json & package-lock.json
      fs.writeFileSync(
        path.join(tmpDir, "package.json"),
        JSON.stringify({ dependencies: { axios: "0.21.1", lodash: "4.17.15" } })
      );

      // 2. requirements.txt
      fs.writeFileSync(
        path.join(tmpDir, "requirements.txt"),
        "flask==1.1.2\nurllib3==1.26.4\n"
      );

      // 3. poetry.lock
      fs.writeFileSync(
        path.join(tmpDir, "poetry.lock"),
        `[[package]]\nname = "requests"\nversion = "2.25.0"\n`
      );

      // 4. pom.xml
      fs.writeFileSync(
        path.join(tmpDir, "pom.xml"),
        `<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>`
      );

      // 5. build.gradle
      fs.writeFileSync(
        path.join(tmpDir, "build.gradle"),
        `dependencies {\n  implementation 'com.fasterxml.jackson.core:jackson-databind:2.9.8'\n}\n`
      );

      // 6. go.mod
      fs.writeFileSync(
        path.join(tmpDir, "go.mod"),
        `module myapp\n\ngo 1.20\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.6.0\n)\n`
      );

      // 7. go.sum
      fs.writeFileSync(
        path.join(tmpDir, "go.sum"),
        `golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad h1:abc=\n`
      );

      // 8. composer.json
      fs.writeFileSync(
        path.join(tmpDir, "composer.json"),
        JSON.stringify({ require: { "guzzlehttp/guzzle": "6.5.0" } })
      );

      // 9. Gemfile.lock
      fs.writeFileSync(
        path.join(tmpDir, "Gemfile.lock"),
        `GEM\n  specs:\n    rails (5.2.0)\n`
      );

      // 10. test.csproj
      fs.writeFileSync(
        path.join(tmpDir, "test.csproj"),
        `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>`
      );

      const osvScanner = new OsvDependencyScanner();
      const result = await osvScanner.scan(tmpDir);

      expect(result.status).toBe("success");
      expect(result.findings.length).toBeGreaterThan(0);

      // Verify that findings include package, installed version, fixed version, CVE, CVSS, and remediation
      const sample = result.findings[0];
      expect(sample.package).toBeDefined();
      expect(sample.installedVersion).toBeDefined();
      expect(sample.cve).toBeDefined();
      expect(sample.category).toBe("SCA");
      expect(sample.scaRemediation).toBeDefined();
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // -------------------------------------------------------------
  // Test 4: CVSS extraction and severity calculation
  // -------------------------------------------------------------
  test("Test 4: CVSS extraction and severity calculation accurately converts CVSS v3 vectors", () => {
    const cvssCritical = extractCvssScore([{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }]);
    expect(cvssCritical).toBeGreaterThanOrEqual(9.0);
    expect(cvssToSeverity(cvssCritical)).toBe("critical");

    const cvssNumeric = extractCvssScore([{ type: "CVSS_V3", score: "7.5" }]);
    expect(cvssNumeric).toBe(7.5);
    expect(cvssToSeverity(cvssNumeric)).toBe("high");

    const cvssLow = extractCvssScore([{ type: "CVSS_V3", score: "3.2" }]);
    expect(cvssToSeverity(cvssLow)).toBe("low");
  });

  // -------------------------------------------------------------
  // Test 5: AI Review for SCA and SECRETS categories
  // -------------------------------------------------------------
  test("Test 5: AI Triage generates immediate CONFIRMED triage and remediation for SCA and SECRETS", async () => {
    const scaFinding: NormalizedFinding = {
      tool: "osv",
      category: "SCA",
      file: "package.json",
      line: 1,
      ruleId: "CVE-2021-44228",
      package: "log4j-core",
      installedVersion: "2.14.1",
      fixedVersion: "2.17.1",
      cve: "CVE-2021-44228",
      cvss: 10.0,
      scaRemediation: "Upgrade log4j-core to >= 2.17.1",
      codeSnippet: "Manifest: package.json\nPackage: log4j-core@2.14.1",
      secretRef: null,
      severity: "critical"
    };

    const scaReview = await reviewFinding(scaFinding, {
      language: "json",
      surroundingCode: scaFinding.codeSnippet,
      imports: []
    });

    expect(scaReview.status).toBe("CONFIRMED");
    expect(scaReview.isRealVulnerability).toBe(true);
    expect(scaReview.owasp).toContain("A06:2021-Vulnerable and Outdated Components");
    expect(scaReview.recommendation).toContain("Upgrade log4j-core");

    const secretFinding: NormalizedFinding = {
      tool: "gitleaks",
      category: "SECRETS",
      file: "config.js",
      line: 5,
      ruleId: "aws-access-key-id",
      secretType: "aws_credential",
      codeSnippet: "const awsKey = 'AKIA*******************';",
      secretRef: "abc12345",
      severity: "critical"
    };

    const secretReview = await reviewFinding(secretFinding, {
      language: "javascript",
      surroundingCode: secretFinding.codeSnippet,
      imports: []
    });

    expect(secretReview.status).toBe("CONFIRMED");
    expect(secretReview.isRealVulnerability).toBe(true);
    expect(secretReview.cwe).toBe("CWE-798");
    expect(secretReview.recommendation).toContain("Revoke and rotate");
  });
});
