# AI Secure SDLC

**An intelligent, production-ready security code review platform that integrates AI-powered vulnerability analysis with your GitHub workflows.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Phase: Production-Ready](https://img.shields.io/badge/Phase-Production%20Ready-brightgreen)
![TypeScript](https://img.shields.io/badge/TypeScript-5.5-blue)
![Node.js](https://img.shields.io/badge/Node.js-20-green)
![React](https://img.shields.io/badge/React-18-blue)

## Overview

AI Secure SDLC automates security code review by combining:

- **🔍 Multi-Scanner Integration**: Semgrep (SAST), Gitleaks (secrets), Trivy (dependencies)
- **🤖 AI-Powered Review**: LLM-based validation of findings with confidence scoring
- **📊 Risk Scoring**: Multi-factor risk calculation (severity, exploitability, business impact, exposure)
- **⏪ GitHub Integration**: Automatic PR checks, comments, and status gates
- **📈 Dashboard**: Real-time scan results and vulnerability tracking
- **🔐 Secret-Safe**: Never stores actual secrets, only hashed references

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      GitHub Repository                       │
│                   (Pull Request Event)                       │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              .github/workflows/security-review.yml           │
│              (Run scanners, trigger webhook)                 │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
        ┌──────────────────────────────────────────┐
        │    AI Secure SDLC Backend (Node.js)      │
        │                                          │
        ├─ Webhook: /api/webhook/github           │
        ├─ Scans: /api/scans                      │
        ├─ Findings: /api/findings                │
        ├─ Repositories: /api/repositories        │
        │                                          │
        └─ Services:                              │
        │  ├─ GitHub API (post comments)          │
        │  ├─ AI Service (LLM review)             │
        │  ├─ Risk Calculator (scoring)           │
        │  └─ Scanner Integration                 │
        │                                          │
        └─────────────────┬─────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
    ┌───────┐         ┌───────┐        ┌────────┐
    │MongoDB│         │GitHub │        │OpenAI/ │
    │  DB   │         │  API  │        │Claude  │
    └───────┘         └───────┘        └────────┘
        ▲
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│              Frontend Dashboard (React + Vite)              │
│                                                             │
│  ┌─────────────────┐  ┌──────────────────────────────┐    │
│  │  Scan List      │  │  Scan Detail + Findings      │    │
│  │  - Status       │  │  - Summary                   │    │
│  │  - Findings     │  │  - Charts                    │    │
│  │  - Gate Result  │  │  - Finding Details           │    │
│  └─────────────────┘  │    • Code Snippet            │    │
│                       │    • AI Review               │    │
│                       │    • Risk Score              │    │
│                       │    • Remediation             │    │
│                       └──────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Features

### Security Scanning
- **Semgrep**: Static application security testing (SAST)
- **Gitleaks**: Detect exposed secrets, API keys, credentials
- **Trivy**: Scan dependencies and container images for vulnerabilities

### AI-Powered Review
- Validates scanner findings with LLM
- Assesses real-world exploitability
- Suggests code patches and remediations
- Calculates confidence scores
- Maps to CWE and OWASP standards

### Risk Scoring (0-100)
- **Severity** (40%): critical, high, medium, low
- **Exploitability** (30%): likelihood of successful exploitation
- **Business Impact** (20%): potential damage to business
- **Exposure** (10%): user-facing vs. internal-only

### GitHub Integration
- Webhook-triggered security gates
- Pull request status checks
- Inline comments with findings and remediation
- Block merging based on policy (critical/high findings)

### Dashboard
- Real-time scan results
- Finding details with AI analysis
- Risk scoring visualization
- Status history

## Quick Start

### Prerequisites
- Node.js 18+
- Docker & Docker Compose (optional)
- MongoDB 6+ (or use Docker)
- GitHub Personal Access Token
- OpenAI/Anthropic API key (for AI review)

### 1. Clone & Install

```bash
git clone <repository>
cd ai-secure-sdlc

# Backend
cd backend
npm install

# Frontend  
cd ../frontend
npm install
```

### 2. Configure Environment

```bash
# Copy and fill in env vars
cp .env.example .env
```

**Required:**
- `MONGO_URI` - MongoDB connection
- `GITHUB_TOKEN` - GitHub PAT
- `GITHUB_WEBHOOK_SECRET` - Webhook secret (32+ chars)
- `AI_API_KEY` - OpenAI/Anthropic key

### 3. Start Services

#### Option A: Docker Compose (Recommended)
```bash
docker-compose up -d
```

Visit:
- **Frontend**: http://localhost:5173
- **Backend**: http://localhost:4000/health
- **MongoDB**: mongodb://admin:admin@localhost:27017

#### Option B: Manual Development
```bash
# Terminal 1: Backend
cd backend
npm run dev

# Terminal 2: Frontend
cd frontend
npm run dev

# Terminal 3: MongoDB
docker run -d -p 27017:27017 -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=admin mongo:7.0
```

### 4. Register Repository

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

Response includes `webhookSecret` — save it for GitHub setup.

### 5. Create GitHub Webhook

1. Go to **Settings → Webhooks → Add webhook**
2. **Payload URL**: `https://<your-domain>/api/webhook/github`
3. **Content type**: `application/json`
4. **Secret**: Use the `webhookSecret` from step 4
5. **Events**: Select `Pull requests`

### 6. Trigger a Scan

1. Create a PR in your repository
2. Workflow runs scanners → sends webhook
3. Backend runs AI review → posts status + comment
4. Check dashboard for results

## API Endpoints

### Scans
- `POST /api/scans` - Create scan
- `GET /api/scans` - List scans
- `GET /api/scans/:id` - Get scan details
- `GET /api/scans/:id/status` - Get minimal status (CI polling)

### Findings
- `GET /api/findings` - List findings (filter by scanId, severity, status)
- `GET /api/findings/:id` - Get finding details
- `PATCH /api/findings/:id` - Update status (false_positive, confirmed, etc.)

### Repositories
- `POST /api/repositories` - Register repository
- `GET /api/repositories` - List repositories
- `GET /api/repositories/:id` - Get repository details

### Webhooks
- `POST /api/webhook/github` - GitHub PR event handler

## Configuration

### Scan Policy

Set in database for each repository:
```javascript
{
  policyConfig: {
    blockCritical: true,      // Block PR if critical found
    blockHigh: true,          // Block PR if high found
    maxAllowedHigh: 0,        // Max high-severity findings
    maxAllowedMedium: 5       // Max medium-severity findings
  }
}
```

### AI Provider

Support for multiple LLM providers via `AI_PROVIDER` env var:
- `openai` (default) - GPT-4, GPT-3.5
- `anthropic` - Claude 3 Sonnet
- `local` - Ollama, LM Studio (basic support)

## Project Structure

```
ai-secure-sdlc/
├── backend/
│   ├── src/
│   │   ├── controllers/        # Request handlers
│   │   ├── models/             # Mongoose schemas
│   │   ├── routes/             # API routes
│   │   ├── services/           # Business logic
│   │   │   ├── aiService.ts
│   │   │   ├── githubService.ts
│   │   │   ├── semgrepService.ts
│   │   │   ├── gitleaksService.ts
│   │   │   ├── trivyService.ts
│   │   │   ├── riskService.ts
│   │   │   └── reportService.ts
│   │   ├── middleware/
│   │   ├── config/
│   │   └── utils/
│   ├── Dockerfile
│   └── package.json
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── SeverityBadge.jsx
│   │   │   └── ScanResultsCard.jsx
│   │   ├── page/
│   │   │   └── Dashboard.jsx
│   │   ├── services/
│   │   │   └── api.js
│   │   └── App.jsx
│   ├── Dockerfile
│   └── package.json
├── .github/workflows/
│   └── security-review.yml
├── docker-compose.yml
├── .env.example
└── README.md
```

## Development Workflow

### Adding a New Scanner

1. Create `src/services/newScannerService.ts`
2. Implement scan method and severity mapping
3. Add to `webhookController.ts` processing pipeline
4. Update GitHub workflow YAML

### Extending AI Review

1. Modify prompt in `aiService.ts:buildReviewPrompt()`
2. Adjust response parsing in `reviewWithOpenAI()`, etc.
3. Test with sample findings

### Customizing Risk Scoring

Edit `riskService.ts:calculateRiskScore()` weights:
- Severity: 40% (default)
- Exploitability: 30%
- Business Impact: 20%
- Exposure: 10%

## Security Considerations

### Secrets Protection
- Never stores raw secrets (database compromise won't leak them)
- Uses `secretRef` (hashed reference) for deduplication
- Gitleaks scans restricted to hash-only storage

### Authentication
- GitHub webhook signature verification (HMAC-SHA256)
- Rate limiting enabled by default
- Helmet security headers
- CORS restricted to frontend origin

### Data Sensitivity
- No stack traces in production errors
- Secrets never logged
- Consider encrypting findings at rest

## Deployment

### Production Checklist

- [ ] Set `NODE_ENV=production`
- [ ] Use managed MongoDB (Atlas, AWS DocumentDB)
- [ ] Enable HTTPS/TLS
- [ ] Set strong, random secrets
- [ ] Configure DNS and domain
- [ ] Set up CI/CD for deployments
- [ ] Enable GitHub Secret Manager for tokens
- [ ] Regular security audits
- [ ] Monitor API usage and costs

### Deployment Options

- **Docker Compose** (single server)
- **Kubernetes** (scale horizontally)
- **AWS ECS** (container orchestration)
- **Heroku** (simple deployment)

## Cost Estimation

### API Calls
- OpenAI: ~$0.01-0.05 per PR (depending on code size)
- Anthropic: Similar
- GitHub: Free (included)

### Infrastructure
- MongoDB: $57+/month (Atlas M0 free tier available)
- Compute: $10-50+/month (depends on load)
- Data transfer: Minimal

Optimize costs with:
- Batch AI reviews
- Cache scanner results
- Implement rate limiting per repository

## Troubleshooting

### Webhook Not Triggering

1. Check GitHub webhook delivery logs (Settings → Webhooks)
2. Verify secret matches `GITHUB_WEBHOOK_SECRET`
3. Confirm backend is publicly accessible
4. Check server logs for errors

### AI Review Failing

1. Verify API key is correct
2. Check API quota/limits
3. Review backend logs
4. Test with simple finding first

### Scan Not Completing

1. Check MongoDB connection
2. Review backend health: `GET /health`
3. Check frontend console for API errors
4. Verify repository is registered

## Contributing

Contributions welcome! Please:
1. Fork repository
2. Create feature branch
3. Add tests
4. Submit PR with clear description

## License

MIT License - see [LICENSE](LICENSE) file

## Roadmap

- [ ] SARIF format export
- [ ] Slack/Teams notifications
- [ ] Batch remediation suggestions
- [ ] False positive ML detection
- [ ] Compliance reports (SOC2, ISO27001)
- [ ] Granular RBAC
- [ ] API authentication (OAuth2)
- [ ] Metrics/analytics dashboard
- [ ] Custom rules engine

## Support

- **Documentation**: See README and inline code comments
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Email**: security@example.com

## Acknowledgments

- Semgrep for SAST rules
- Gitleaks for secret detection
- Trivy for vulnerability scanning
- OpenAI/Anthropic for LLM APIs
- GitHub for webhook infrastructure

---

**Built for DevSecOps teams who want intelligent, automated security review integrated into their development workflow.**
