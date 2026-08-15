# API Documentation - AI Secure SDLC

Complete API reference for the AI Secure SDLC platform.

## Base URL

```
http://localhost:4000/api
```

Production: `https://api.your-domain.com/api`

## Authentication

Currently, all endpoints are unauthenticated. Future versions will support:
- JWT Bearer tokens
- GitHub OAuth
- API keys

## Rate Limiting

- 100 requests per 15 minutes
- Applies to all endpoints
- Headers: `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`

---

## Health Check

### GET /health

Check if the backend is running.

**Response:**
```json
{
  "status": "ok",
  "service": "ai-secure-sdlc-backend"
}
```

---

## Scans

### POST /api/scans

Create a new security scan.

**Request:**
```bash
curl -X POST http://localhost:4000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "repositoryId": "507f1f77bcf86cd799439011",
    "prNumber": 42,
    "commitSha": "abc123def456abc123def456",
    "triggeredBy": "github-actions"
  }'
```

**Parameters:**
| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `repositoryId` | ObjectId | Yes | Valid repository ID |
| `prNumber` | number | Yes | Pull request number |
| `commitSha` | string | Yes | Git commit SHA (7+ chars) |
| `triggeredBy` | string | Yes | Who triggered the scan |

**Response (201):**
```json
{
  "success": true,
  "data": {
    "_id": "507f1f77bcf86cd799439012",
    "repositoryId": "507f1f77bcf86cd799439011",
    "prNumber": 42,
    "commitSha": "abc123def456abc123def456",
    "status": "pending",
    "triggeredBy": "github-actions",
    "startedAt": "2024-01-15T10:30:00Z",
    "summary": {
      "critical": 0,
      "high": 0,
      "medium": 0,
      "low": 0,
      "total": 0
    },
    "gateResult": "pending"
  }
}
```

**Errors:**
- `400` - Invalid payload
- `404` - Repository not found

---

### GET /api/scans

List all scans, optionally filtered by repository.

**Request:**
```bash
# List all scans
curl http://localhost:4000/api/scans

# Filter by repository
curl http://localhost:4000/api/scans?repositoryId=507f1f77bcf86cd799439011
```

**Query Parameters:**
| Parameter | Type | Optional | Notes |
|-----------|------|----------|-------|
| `repositoryId` | ObjectId | Yes | Filter by repository |

**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "_id": "507f1f77bcf86cd799439012",
      "repositoryId": "507f1f77bcf86cd799439011",
      "prNumber": 42,
      "commitSha": "abc123def456abc123def456",
      "status": "completed",
      "triggeredBy": "github-actions",
      "startedAt": "2024-01-15T10:30:00Z",
      "completedAt": "2024-01-15T10:35:00Z",
      "summary": {
        "critical": 1,
        "high": 3,
        "medium": 5,
        "low": 2,
        "total": 11
      },
      "gateResult": "fail"
    }
  ]
}
```

---

### GET /api/scans/:id

Get detailed information about a specific scan.

**Request:**
```bash
curl http://localhost:4000/api/scans/507f1f77bcf86cd799439012
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "_id": "507f1f77bcf86cd799439012",
    "repositoryId": "507f1f77bcf86cd799439011",
    "prNumber": 42,
    "commitSha": "abc123def456abc123def456",
    "status": "completed",
    "triggeredBy": "github-actions",
    "startedAt": "2024-01-15T10:30:00Z",
    "completedAt": "2024-01-15T10:35:00Z",
    "summary": {
      "critical": 1,
      "high": 3,
      "medium": 5,
      "low": 2,
      "total": 11
    },
    "gateResult": "fail",
    "createdAt": "2024-01-15T10:30:00Z",
    "updatedAt": "2024-01-15T10:35:00Z"
  }
}
```

**Errors:**
- `404` - Scan not found

---

### GET /api/scans/:id/status

Get minimal scan status (optimized for CI polling).

**Request:**
```bash
curl http://localhost:4000/api/scans/507f1f77bcf86cd799439012/status
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "status": "completed",
    "gateResult": "fail",
    "summary": {
      "critical": 1,
      "high": 3,
      "medium": 5,
      "low": 2,
      "total": 11
    }
  }
}
```

---

## Findings

### GET /api/findings

List findings with optional filtering.

**Request:**
```bash
# All findings
curl http://localhost:4000/api/findings

# By scan
curl http://localhost:4000/api/findings?scanId=507f1f77bcf86cd799439012

# By repository
curl http://localhost:4000/api/findings?repositoryId=507f1f77bcf86cd799439011

# By severity
curl http://localhost:4000/api/findings?severity=critical

# By status
curl http://localhost:4000/api/findings?status=open

# Combined
curl "http://localhost:4000/api/findings?scanId=507f1f77bcf86cd799439012&severity=high&status=open"
```

**Query Parameters:**
| Parameter | Type | Optional | Values |
|-----------|------|----------|--------|
| `scanId` | ObjectId | Yes | Valid scan ID |
| `repositoryId` | ObjectId | Yes | Valid repository ID |
| `severity` | string | Yes | critical, high, medium, low |
| `status` | string | Yes | open, false_positive, confirmed, remediated |

**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "_id": "507f1f77bcf86cd799439013",
      "scanId": "507f1f77bcf86cd799439012",
      "repositoryId": "507f1f77bcf86cd799439011",
      "tool": "semgrep",
      "file": "src/auth/login.ts",
      "line": 42,
      "ruleId": "js.express.security.injection.sql.sql-injection",
      "codeSnippet": "const query = `SELECT * FROM users WHERE id = ${userId}`;",
      "secretRef": null,
      "severity": "high",
      "status": "open",
      "ai": {
        "isRealVulnerability": true,
        "confidence": 95,
        "attackScenario": "An attacker can inject SQL commands via the userId parameter...",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "exploitability": "high",
        "remediation": {
          "patch": "const query = 'SELECT * FROM users WHERE id = ?'; db.query(query, [userId]);",
          "explanation": "Use parameterized queries to prevent SQL injection attacks."
        }
      },
      "risk": {
        "score": 78,
        "severityWeight": 30,
        "exploitabilityWeight": 30,
        "businessImpactWeight": 15,
        "exposureWeight": 3
      }
    }
  ],
  "count": 1
}
```

---

### GET /api/findings/:id

Get detailed information about a specific finding.

**Request:**
```bash
curl http://localhost:4000/api/findings/507f1f77bcf86cd799439013
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "_id": "507f1f77bcf86cd799439013",
    "scanId": "507f1f77bcf86cd799439012",
    "repositoryId": "507f1f77bcf86cd799439011",
    "tool": "gitleaks",
    "file": ".env.production",
    "line": 3,
    "ruleId": "slack-bot-token",
    "codeSnippet": "SLACK_TOKEN=xoxb-1234567890-1234567890-...",
    "secretRef": "a1b2c3d4e5f6g7h8",
    "severity": "critical",
    "status": "open",
    "ai": {
      "isRealVulnerability": true,
      "confidence": 100,
      "attackScenario": "An attacker with this token can impersonate the bot and access Slack workspace...",
      "cwe": "CWE-798",
      "owasp": "A02:2021",
      "exploitability": "high",
      "remediation": {
        "patch": "Move secrets to environment variables or a secrets manager",
        "explanation": "Never commit secrets to the repository. Use GitHub Secrets for CI/CD."
      }
    },
    "risk": {
      "score": 95,
      "severityWeight": 40,
      "exploitabilityWeight": 30,
      "businessImpactWeight": 20,
      "exposureWeight": 5
    }
  }
}
```

**Errors:**
- `404` - Finding not found

---

### PATCH /api/findings/:id

Update finding status.

**Request:**
```bash
curl -X PATCH http://localhost:4000/api/findings/507f1f77bcf86cd799439013 \
  -H "Content-Type: application/json" \
  -d '{"status": "false_positive"}'
```

**Parameters:**
| Field | Type | Required | Values |
|-------|------|----------|--------|
| `status` | string | Yes | open, false_positive, confirmed, remediated |

**Response (200):**
```json
{
  "success": true,
  "data": {
    "_id": "507f1f77bcf86cd799439013",
    "status": "false_positive",
    "updatedAt": "2024-01-15T10:40:00Z"
  }
}
```

**Errors:**
- `400` - Invalid status value
- `404` - Finding not found

---

## Repositories

### POST /api/repositories

Register a new repository for security scanning.

**Request:**
```bash
curl -X POST http://localhost:4000/api/repositories \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-repo",
    "owner": "my-org",
    "githubUrl": "https://github.com/my-org/my-repo",
    "defaultBranch": "main"
  }'
```

**Parameters:**
| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | string | Yes | Repository name |
| `owner` | string | Yes | GitHub organization/user |
| `githubUrl` | string | Yes | Full GitHub URL |
| `defaultBranch` | string | No | Default: "main" |

**Response (201):**
```json
{
  "success": true,
  "data": {
    "id": "507f1f77bcf86cd799439014",
    "name": "my-repo",
    "owner": "my-org",
    "githubUrl": "https://github.com/my-org/my-repo",
    "defaultBranch": "main",
    "webhookSecret": "c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"
  }
}
```

**Important:** Save the `webhookSecret` immediately — it's only returned once!

**Errors:**
- `400` - Invalid payload
- `409` - Repository already registered

---

### GET /api/repositories

List all registered repositories.

**Request:**
```bash
curl http://localhost:4000/api/repositories
```

**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "_id": "507f1f77bcf86cd799439014",
      "name": "my-repo",
      "owner": "my-org",
      "githubUrl": "https://github.com/my-org/my-repo",
      "defaultBranch": "main",
      "isActive": true,
      "scanConfig": {
        "enableSemgrep": true,
        "enableGitleaks": true,
        "enableTrivy": false
      },
      "policyConfig": {
        "blockCritical": true,
        "blockHigh": true,
        "maxAllowedHigh": 0,
        "maxAllowedMedium": 5
      },
      "createdAt": "2024-01-15T10:00:00Z",
      "updatedAt": "2024-01-15T10:00:00Z"
    }
  ]
}
```

---

### GET /api/repositories/:id

Get details about a specific repository.

**Request:**
```bash
curl http://localhost:4000/api/repositories/507f1f77bcf86cd799439014
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "_id": "507f1f77bcf86cd799439014",
    "name": "my-repo",
    "owner": "my-org",
    "githubUrl": "https://github.com/my-org/my-repo",
    "defaultBranch": "main",
    "isActive": true,
    "scanConfig": {
      "enableSemgrep": true,
      "enableGitleaks": true,
      "enableTrivy": false
    },
    "policyConfig": {
      "blockCritical": true,
      "blockHigh": true,
      "maxAllowedHigh": 0,
      "maxAllowedMedium": 5
    }
  }
}
```

**Errors:**
- `404` - Repository not found

---

## Webhooks

### POST /api/webhook/github

GitHub webhook endpoint for PR events.

**Headers (sent by GitHub):**
```
X-Hub-Signature-256: sha256=...
X-GitHub-Event: pull_request
```

**Request Body (GitHub sends):**
```json
{
  "action": "opened",
  "pull_request": {
    "number": 42,
    "title": "Add user authentication",
    "body": "Implements OAuth2 login flow",
    "head": {
      "sha": "abc123def456abc123def456",
      "ref": "feature/auth",
      "repo": {
        "name": "my-repo",
        "full_name": "my-org/my-repo",
        "owner": {
          "login": "my-org"
        }
      }
    }
  }
}
```

**Response (202):**
```json
{
  "success": true,
  "message": "Scan initiated",
  "scanId": "507f1f77bcf86cd799439012"
}
```

Processing happens asynchronously. Check `/api/scans/:scanId/status` for progress.

**Errors:**
- `400` - Invalid payload
- `401` - Invalid signature
- `404` - Repository not registered

---

## Error Responses

All errors follow this format:

```json
{
  "success": false,
  "message": "Error description"
}
```

**Common HTTP Status Codes:**
| Code | Meaning |
|------|---------|
| 200 | Success |
| 201 | Created |
| 202 | Accepted (async processing) |
| 400 | Bad request |
| 401 | Unauthorized |
| 404 | Not found |
| 409 | Conflict (e.g., duplicate) |
| 429 | Rate limited |
| 500 | Server error |

---

## Rate Limit Headers

Every response includes:

```
RateLimit-Limit: 100
RateLimit-Remaining: 95
RateLimit-Reset: 1705315200
```

`RateLimit-Reset` is a Unix timestamp when the quota resets.

---

## Pagination (Future)

Will support pagination for large datasets:

```
GET /api/findings?page=2&limit=50
```

For now, all endpoints return up to 200 results.

---

## SDKs & Clients

### cURL

Used throughout this documentation.

### JavaScript/TypeScript

```typescript
import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:4000/api"
});

// List scans
const scans = await api.get("/scans");

// Create scan
const newScan = await api.post("/scans", {
  repositoryId: "...",
  prNumber: 42,
  commitSha: "abc123...",
  triggeredBy: "github-actions"
});
```

### Python

```python
import requests

api = requests.Session()
api.base_url = "http://localhost:4000/api"

# List scans
scans = api.get("/scans").json()

# Get specific scan
scan = api.get(f"/scans/{scan_id}").json()
```

---

## Next Steps

1. [Getting Started](README.md)
2. [Development Guide](DEVELOPMENT.md)
3. [GitHub Integration Setup](README.md#5-create-github-webhook)
