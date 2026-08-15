# Development Guide - AI Secure SDLC

This guide helps developers extend, customize, and contribute to the AI Secure SDLC platform.

## Table of Contents

1. [Development Setup](#development-setup)
2. [Architecture Deep Dive](#architecture-deep-dive)
3. [Adding New Scanners](#adding-new-scanners)
4. [Extending AI Review](#extending-ai-review)
5. [Customizing Risk Scoring](#customizing-risk-scoring)
6. [Testing](#testing)
7. [Debugging](#debugging)
8. [Performance Optimization](#performance-optimization)

## Development Setup

### Backend Development

```bash
cd backend

# Install dependencies
npm install

# Start with auto-reload
npm run dev

# Build production bundle
npm run build

# Run linter
npm run lint

# Run tests
npm test
```

**Key files:**
- `src/server.ts` - Express app setup
- `src/models/` - Mongoose schemas
- `src/controllers/` - Request handlers
- `src/services/` - Business logic
- `src/routes/` - API endpoints

### Frontend Development

```bash
cd frontend

# Install dependencies
npm install

# Start dev server (hot reload)
npm run dev

# Build production bundle
npm run build

# Preview production build
npm run preview

# Run linter
npm run lint
```

**Key files:**
- `src/App.jsx` - Main app component
- `src/page/Dashboard.jsx` - Dashboard page
- `src/components/` - Reusable components
- `src/services/api.js` - API client

### Database

```bash
# Start MongoDB
docker run -d -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=admin \
  mongo:7.0

# Connect with MongoDB Compass
# Connection string: mongodb://admin:admin@localhost:27017/ai_secure_sdlc?authSource=admin
```

## Architecture Deep Dive

### Request Flow

```
GitHub PR Event
    ↓
GitHub Actions Workflow
    ↓
Run Scanners (Semgrep, Gitleaks, Trivy)
    ↓
POST /api/webhook/github
    ↓
Backend: Create Scan Record
    ↓
Run Scanner Services in Parallel
    ↓
For each finding:
    - AI Service: Review finding
    - Risk Service: Calculate score
    - Persist to MongoDB
    ↓
Update Scan Status & Gate Result
    ↓
GitHub Service: Post PR comment + check run
    ↓
Frontend: Fetch and display results
```

### Data Models

#### Scan
- Represents a single PR security scan
- Tracks overall status (pending → scanning → ai_review → completed)
- Stores finding counts and gate result

```typescript
interface IScan {
  repositoryId: ObjectId;
  prNumber: number;
  commitSha: string;
  status: "pending" | "scanning" | "ai_review" | "completed" | "failed";
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  gateResult: "pass" | "fail" | "pending";
}
```

#### Finding
- Individual vulnerability found by a scanner
- Includes AI review and risk assessment
- Updateable status (false_positive, confirmed, remediated)

```typescript
interface IFinding {
  scanId: ObjectId;
  repositoryId: ObjectId;
  tool: "semgrep" | "gitleaks" | "trivy";
  file: string;
  line: number;
  ruleId: string;
  severity: "critical" | "high" | "medium" | "low";
  status: "open" | "false_positive" | "confirmed" | "remediated";
  ai?: {
    isRealVulnerability: boolean;
    confidence: number;
    attackScenario: string;
    cwe: string;
    owasp: string;
    remediation: { patch: string; explanation: string };
  };
  risk?: {
    score: number;
    severityWeight: number;
    exploitabilityWeight: number;
    businessImpactWeight: number;
    exposureWeight: number;
  };
}
```

#### Repository
- Registered GitHub repository
- Contains scan config and security policy

## Adding New Scanners

### 1. Create Scanner Service

```typescript
// src/services/newScannerService.ts
export class NewScannerService {
  async scan(repoPath: string): Promise<Finding[]> {
    // Execute scanner
    // Parse output
    // Return findings
  }

  static mapSeverity(scannerSeverity: string): "critical" | "high" | "medium" | "low" {
    // Convert scanner severity to unified format
  }
}
```

### 2. Add to Webhook Processing

Edit `src/controllers/webhookController.ts`:

```typescript
if (repository.scanConfig.enableMyScanner) {
  const findings = await runMyScanner(repository, prData);
  allFindings.push(...findings);
}
```

### 3. Update GitHub Workflow

Edit `.github/workflows/security-review.yml`:

```yaml
- name: Run My Scanner
  id: myscanner
  run: |
    myscanner scan . --report-path myscanner-report.json
```

### 4. Update Repository Model

Add to `scanConfig`:

```typescript
scanConfig: {
  enableMyScanner: { type: Boolean, default: true }
}
```

## Extending AI Review

### Current Prompt Format

The AI Service sends findings to the LLM with context:

```
- Tool: <scanner name>
- Rule: <rule id>
- File: <file path>
- Severity: <original severity>
- Code: <snippet>
- PR Title: <title>
- PR Body: <description>
```

### Customize the Prompt

Edit `src/services/aiService.ts:buildReviewPrompt()`:

```typescript
private buildReviewPrompt(req: AIReviewRequest): string {
  // Modify prompt to ask for additional fields
  // Example: ask for CVSS score, proof-of-concept, etc.
  return `...`
}
```

### Parse Additional AI Response

Edit the `AIReviewResult` interface and parsing:

```typescript
export interface AIReviewResult {
  // ...existing fields...
  cvssScore: number;           // NEW
  proofOfConcept: string;     // NEW
  affectedUsers: number;      // NEW
}
```

### Test AI Integration

Create a test file:

```typescript
// test/aiService.test.ts
import { AIService } from "../src/services/aiService";

describe("AIService", () => {
  it("should review a finding", async () => {
    const service = new AIService(process.env.AI_API_KEY);
    const result = await service.reviewFinding({
      finding: { /* test data */ }
    });
    expect(result.isRealVulnerability).toBeDefined();
  });
});
```

## Customizing Risk Scoring

### Modify Weights

The default weights are in `src/services/riskService.ts`:

```typescript
// Weights (must sum to 100)
static calculateRiskScore(factors: RiskFactors): RiskScore {
  const severityScore = RiskService.severityToScore(factors.severity) * 0.4;  // 40%
  const exploitabilityScore = RiskService.exploitabilityToScore(factors.exploitability) * 0.3;  // 30%
  const businessImpactScore = RiskService.businessImpactToScore(factors.businessImpact) * 0.2;  // 20%
  const exposureScore = RiskService.exposureToScore(factors.exposure) * 0.1;  // 10%
  // ...
}
```

To change weights:
```typescript
// Example: emphasize exploitability
const severityScore = ... * 0.3;           // 30%
const exploitabilityScore = ... * 0.4;    // 40% (increased)
const businessImpactScore = ... * 0.2;    // 20%
const exposureScore = ... * 0.1;          // 10%
```

### Add Custom Factors

```typescript
export interface RiskFactors {
  // ...existing...
  timeToExploit: "minutes" | "hours" | "days";  // NEW
  detectability: "easy" | "medium" | "hard";    // NEW
}
```

## Testing

### Unit Tests

```bash
cd backend
npm test

# Watch mode
npm test -- --watch

# Coverage
npm test -- --coverage
```

### Integration Tests

```typescript
// test/api.integration.ts
import request from "supertest";
import app from "../src/server";

describe("POST /api/scans", () => {
  it("should create a scan", async () => {
    const response = await request(app)
      .post("/api/scans")
      .send({
        repositoryId: "...",
        prNumber: 123,
        commitSha: "abc123...",
        triggeredBy: "github-actions"
      });

    expect(response.status).toBe(201);
    expect(response.body.data._id).toBeDefined();
  });
});
```

### Frontend Component Tests

```typescript
// frontend/src/components/__tests__/SeverityBadge.test.jsx
import { render, screen } from "@testing-library/react";
import SeverityBadge from "../SeverityBadge";

describe("SeverityBadge", () => {
  it("renders critical severity", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("critical")).toBeInTheDocument();
  });
});
```

## Debugging

### Backend Debugging

Using VS Code debugger:

1. Create `.vscode/launch.json`:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "node",
      "request": "launch",
      "name": "Backend",
      "program": "${workspaceFolder}/backend/src/server.ts",
      "preLaunchTask": "npm: dev (backend)",
      "outFiles": ["${workspaceFolder}/backend/dist/**/*.js"]
    }
  ]
}
```

2. Set breakpoints and run debugger

### Check Logs

```bash
# Backend logs (if using Docker)
docker logs ai-secure-sdlc-backend

# MongoDB logs
docker logs ai-secure-sdlc-db

# View recent scans
curl http://localhost:4000/api/scans

# View specific scan
curl http://localhost:4000/api/scans/SCAN_ID

# View findings
curl http://localhost:4000/api/findings?scanId=SCAN_ID
```

### Debug Webhook Signature

```typescript
import crypto from "crypto";

const payload = "...";
const secret = "webhook_secret";
const hash = crypto.createHmac("sha256", secret).update(payload).digest("hex");
console.log(`Expected: sha256=${hash}`);
console.log(`Received: ${req.headers["x-hub-signature-256"]}`);
```

## Performance Optimization

### Database Indexing

Add indexes in `src/models/`:

```typescript
// Good for CI polling
scanSchema.index({ repositoryId: 1, prNumber: 1, commitSha: 1 });

// Good for finding queries
findingSchema.index({ scanId: 1, severity: 1 });
```

### Caching

Implement Redis caching for frequently accessed data:

```typescript
import Redis from "ioredis";

const redis = new Redis();

export async function getFindingsWithCache(scanId: string) {
  const cached = await redis.get(`findings:${scanId}`);
  if (cached) return JSON.parse(cached);

  const findings = await Finding.find({ scanId });
  await redis.setex(`findings:${scanId}`, 3600, JSON.stringify(findings));
  return findings;
}
```

### Batch Processing

Process multiple findings in parallel:

```typescript
const results = await Promise.all(
  findings.map(f => aiService.reviewFinding(f))
);
```

### Pagination

Implement pagination for large result sets:

```typescript
const page = req.query.page || 1;
const limit = 50;
const skip = (page - 1) * limit;

const findings = await Finding.find(filter)
  .skip(skip)
  .limit(limit)
  .sort({ createdAt: -1 });
```

## Contributing

1. Create a feature branch
2. Make changes following code style
3. Add tests for new functionality
4. Update documentation
5. Submit PR with clear description

## Resources

- [Express.js Documentation](https://expressjs.com/)
- [Mongoose Documentation](https://mongoosejs.com/)
- [React Documentation](https://react.dev/)
- [TypeScript Handbook](https://www.typescriptlang.org/docs/)
- [GitHub API Reference](https://docs.github.com/en/rest)

## Support

Questions or issues? Open a GitHub issue with:
- Description of the problem
- Steps to reproduce
- Expected vs. actual behavior
- Environment (Node version, OS, etc.)
