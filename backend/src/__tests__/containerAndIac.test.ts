import { ContainerScanner } from "../services/scanners/containerScannerService";
import { IacScanner } from "../services/scanners/iacScannerService";
import { reviewFinding } from "../services/ai/aiReviewerService";
import { computeRisk } from "../services/riskService";
import { NormalizedFinding } from "../services/scanners/types";
import path from "path";
import fs from "fs";
import os from "os";

describe("Container & IaC Security Test Suite", () => {
  jest.setTimeout(60000);

  // -------------------------------------------------------------
  // Test 1: Dockerfile Security Scanning
  // -------------------------------------------------------------
  test("Test 1: ContainerScanner detects root user, latest tags, exposed secrets, missing healthcheck in Dockerfile", async () => {
    const tmpDir = path.join(os.tmpdir(), `container-test-${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });

    try {
      const dockerfileContent = `
        FROM node:latest
        ENV API_SECRET_KEY=superSecretJwtSigningToken12345
        RUN apt-get update && apt-get install -y sudo netcat
        USER root
        WORKDIR /app
        COPY . .
        CMD ["node", "server.js"]
      `;

      fs.writeFileSync(path.join(tmpDir, "Dockerfile"), dockerfileContent, "utf-8");

      const scanner = new ContainerScanner();
      const result = await scanner.scan(tmpDir);

      expect(result.status).toBe("success");
      expect(result.findings.length).toBeGreaterThanOrEqual(3);

      const rules = result.findings.map((f) => f.ruleId);

      expect(rules.some((r) => r.includes("latest") || r.includes("tag"))).toBe(true);
      expect(rules.some((r) => r.includes("root") || r.includes("user"))).toBe(true);
      expect(rules.some((r) => r.includes("secret") || r.includes("env"))).toBe(true);

      // Verify category
      for (const finding of result.findings) {
        expect(finding.category).toBe("CONTAINER");
        expect(finding.iacPlatform).toBe("docker");
        // Verify secrets are masked
        if (finding.ruleId.includes("secret")) {
          expect(finding.codeSnippet).not.toContain("superSecretJwtSigningToken12345");
        }
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // -------------------------------------------------------------
  // Test 2: docker-compose.yml / yaml Security Scanning
  // -------------------------------------------------------------
  test("Test 2: ContainerScanner detects privileged containers, unsafe capabilities, socket mounts and plaintext secrets in docker-compose.yml", async () => {
    const tmpDir = path.join(os.tmpdir(), `compose-test-${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });

    try {
      const composeContent = `
version: '3.8'
services:
  web:
    image: nginx:1.21
    privileged: true
    cap_add:
      - SYS_ADMIN
      - ALL
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    network_mode: host
    environment:
      - DATABASE_PASSWORD=SuperDbSecretPassword123
      `;

      fs.writeFileSync(path.join(tmpDir, "docker-compose.yml"), composeContent, "utf-8");

      const scanner = new ContainerScanner();
      const result = await scanner.scan(tmpDir);

      expect(result.status).toBe("success");
      expect(result.findings.length).toBeGreaterThanOrEqual(4);

      const rules = result.findings.map((f) => f.ruleId);
      expect(rules.some((r) => r.includes("privileged"))).toBe(true);
      expect(rules.some((r) => r.includes("capabilities"))).toBe(true);
      expect(rules.some((r) => r.includes("socket"))).toBe(true);
      expect(rules.some((r) => r.includes("secret") || r.includes("plaintext"))).toBe(true);

      // Check masking
      const secretFinding = result.findings.find((f) => f.ruleId.includes("secret"));
      if (secretFinding) {
        expect(secretFinding.codeSnippet).not.toContain("SuperDbSecretPassword123");
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // -------------------------------------------------------------
  // Test 3: Terraform IaC Security Scanning
  // -------------------------------------------------------------
  test("Test 3: IacScanner detects 0.0.0.0/0 exposure, public S3 buckets, wildcard IAM, and hardcoded secrets in Terraform", async () => {
    const tmpDir = path.join(os.tmpdir(), `tf-test-${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });

    try {
      const tfContent = `
resource "aws_security_group" "web_sg" {
  name = "web-sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "public_bucket" {
  bucket = "company-sensitive-data"
  acl    = "public-read"
}

resource "aws_iam_policy" "admin_policy" {
  name = "overprivileged_admin"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Resource = "*"
        Effect   = "Allow"
      }
    ]
  })
}

variable "db_password" {
  default = "HardcodedPlaintextPassword123"
}
      `;

      fs.writeFileSync(path.join(tmpDir, "main.tf"), tfContent, "utf-8");

      const scanner = new IacScanner();
      const result = await scanner.scan(tmpDir);

      expect(result.status).toBe("success");
      expect(result.findings.length).toBeGreaterThanOrEqual(4);

      const rules = result.findings.map((f) => f.ruleId);
      expect(rules.some((r) => r.includes("cidr") || r.includes("0.0.0.0"))).toBe(true);
      expect(rules.some((r) => r.includes("s3") || r.includes("public"))).toBe(true);
      expect(rules.some((r) => r.includes("iam") || r.includes("admin"))).toBe(true);
      expect(rules.some((r) => r.includes("secret") || r.includes("password"))).toBe(true);

      for (const f of result.findings) {
        expect(f.category).toBe("IAC");
        expect(f.iacPlatform).toBe("terraform");
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // -------------------------------------------------------------
  // Test 4: Kubernetes IaC Security Scanning
  // -------------------------------------------------------------
  test("Test 4: IacScanner detects privileged pods, root execution, cluster-admin bindings, and hostPath mounts in Kubernetes", async () => {
    const tmpDir = path.join(os.tmpdir(), `k8s-test-${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });

    try {
      const k8sContent = `
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      privileged: true
      runAsNonRoot: false
      runAsUser: 0
    volumeMounts:
    - mountPath: /host
      name: host-vol
  volumes:
  - name: host-vol
    hostPath:
      path: /etc
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dangerous-binding
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: unencrypted-secret
data:
  api_key: "UnencryptedPlaintextToken98765"
      `;

      fs.writeFileSync(path.join(tmpDir, "deployment.yaml"), k8sContent, "utf-8");

      const scanner = new IacScanner();
      const result = await scanner.scan(tmpDir);

      expect(result.status).toBe("success");
      expect(result.findings.length).toBeGreaterThanOrEqual(4);

      const rules = result.findings.map((f) => f.ruleId);
      expect(rules.some((r) => r.includes("privileged"))).toBe(true);
      expect(rules.some((r) => r.includes("root") || r.includes("user"))).toBe(true);
      expect(rules.some((r) => r.includes("cluster-admin"))).toBe(true);
      expect(rules.some((r) => r.includes("hostpath"))).toBe(true);
      expect(rules.some((r) => r.includes("configmap") || r.includes("secret"))).toBe(true);

      for (const f of result.findings) {
        expect(f.category).toBe("IAC");
        expect(f.iacPlatform).toBe("kubernetes");
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // -------------------------------------------------------------
  // Test 5: AI Triage & Risk Assessment for Container & IaC
  // -------------------------------------------------------------
  test("Test 5: AI Triage and Risk scoring accurately evaluates Container and IaC misconfigurations", async () => {
    const containerFinding: NormalizedFinding = {
      tool: "container-scanner",
      category: "CONTAINER",
      file: "Dockerfile",
      line: 4,
      ruleId: "docker-running-as-root",
      title: "Container Explicitly Configured to Run as Root",
      codeSnippet: "USER root",
      secretRef: null,
      iacPlatform: "docker",
      complianceStandard: "CIS Docker Benchmark 4.1",
      severity: "high"
    };

    const containerReview = await reviewFinding(containerFinding, {
      language: "dockerfile",
      surroundingCode: containerFinding.codeSnippet,
      imports: []
    });

    expect(containerReview.status).toBe("CONFIRMED");
    expect(containerReview.isRealVulnerability).toBe(true);
    expect(containerReview.secureFix).toContain("USER appuser");

    const containerRisk = computeRisk(containerFinding, containerReview);
    expect(containerRisk.score).toBeGreaterThanOrEqual(65);
    expect(containerRisk.decision).toBe("BLOCK");

    const iacFinding: NormalizedFinding = {
      tool: "iac-scanner",
      category: "IAC",
      file: "main.tf",
      line: 8,
      ruleId: "tf-unrestricted-cidr-exposure",
      title: "Critical Port Open to the Public Internet (0.0.0.0/0 Exposure)",
      codeSnippet: "cidr_blocks = [\"0.0.0.0/0\"]",
      secretRef: null,
      iacPlatform: "terraform",
      complianceStandard: "CIS AWS Benchmark 4.1",
      severity: "critical"
    };

    const iacReview = await reviewFinding(iacFinding, {
      language: "terraform",
      surroundingCode: iacFinding.codeSnippet,
      imports: []
    });

    expect(iacReview.status).toBe("CONFIRMED");
    expect(iacReview.isRealVulnerability).toBe(true);
    expect(iacReview.secureFix).toContain("cidr_blocks");

    const iacRisk = computeRisk(iacFinding, iacReview);
    expect(iacRisk.score).toBeGreaterThanOrEqual(85);
    expect(iacRisk.decision).toBe("BLOCK");
  });
});
