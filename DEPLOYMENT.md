# Deployment & Troubleshooting Guide

## Deployment

### Pre-Deployment Checklist

- [ ] Environment variables configured (`GITHUB_TOKEN`, `AI_API_KEY`, `MONGO_URI`)
- [ ] Set `NODE_ENV=production`
- [ ] MongoDB is accessible and initialized
- [ ] GitHub webhook secret is strong and random (32+ characters)
- [ ] HTTPS/TLS configured
- [ ] Rate limiting configured appropriately
- [ ] Secrets stored securely (GitHub Secrets, env var manager)
- [ ] Backups enabled for database
- [ ] Monitoring/alerting configured

### Local Deployment

#### Using Docker Compose (Recommended)

```bash
# 1. Clone repository
git clone <repo>
cd ai-secure-sdlc

# 2. Copy and configure .env
cp .env.example .env
# Edit .env with your values

# 3. Build and start services
docker-compose up -d

# 4. Verify services are running
docker-compose ps

# Output should show all services as healthy
```

#### Manual Startup

```bash
# Terminal 1: MongoDB
docker run -d -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=admin \
  -v mongodb_data:/data/db \
  mongo:7.0

# Terminal 2: Backend
cd backend
npm install
npm run build
NODE_ENV=production PORT=4000 npm start

# Terminal 3: Frontend
cd frontend
npm install
npm run build
# Serve dist/ with nginx or any web server
```

### Cloud Deployment

#### AWS ECS + RDS

```bash
# Build and push Docker images
docker build -t my-registry/ai-secure-backend:latest backend/
docker build -t my-registry/ai-secure-frontend:latest frontend/

aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 123456789.dkr.ecr.us-east-1.amazonaws.com

docker push 123456789.dkr.ecr.us-east-1.amazonaws.com/ai-secure-backend:latest
docker push 123456789.dkr.ecr.us-east-1.amazonaws.com/ai-secure-frontend:latest

# Create ECS task definitions, services, etc.
# Update environment variables in task definition
```

#### Heroku

```bash
# Create Heroku apps
heroku create ai-secure-backend
heroku create ai-secure-frontend

# Set environment variables
heroku config:set GITHUB_TOKEN=... --app ai-secure-backend
heroku config:set MONGO_URI=... --app ai-secure-backend
heroku config:set AI_API_KEY=... --app ai-secure-backend

# Configure MongoDB add-on
heroku addons:create mongolab:sandbox --app ai-secure-backend

# Deploy
git push heroku main
```

#### Kubernetes

```yaml
# backend-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ai-secure-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ai-secure-backend
  template:
    metadata:
      labels:
        app: ai-secure-backend
    spec:
      containers:
      - name: backend
        image: my-registry/ai-secure-backend:latest
        ports:
        - containerPort: 4000
        env:
        - name: MONGO_URI
          valueFrom:
            secretKeyRef:
              name: ai-secure-secrets
              key: mongo-uri
        - name: GITHUB_TOKEN
          valueFrom:
            secretKeyRef:
              name: ai-secure-secrets
              key: github-token
        - name: AI_API_KEY
          valueFrom:
            secretKeyRef:
              name: ai-secure-secrets
              key: ai-api-key
        livenessProbe:
          httpGet:
            path: /health
            port: 4000
          initialDelaySeconds: 30
          periodSeconds: 10
```

Deploy:
```bash
kubectl apply -f backend-deployment.yaml
kubectl apply -f frontend-deployment.yaml
kubectl apply -f service.yaml
```

---

## Troubleshooting

### Backend Issues

#### Port Already in Use

```bash
# Kill process on port 4000
lsof -i :4000
kill -9 <PID>

# Or use a different port
PORT=4001 npm start
```

#### MongoDB Connection Failed

```bash
# Check MongoDB is running
docker ps | grep mongo

# Check credentials
mongosh "mongodb://admin:admin@localhost:27017" --authenticationDatabase admin

# Connection string format
mongodb://[username]:[password]@[host]:[port]/[database]?authSource=admin
```

#### Health Check Failing

```bash
# Test endpoint directly
curl http://localhost:4000/health

# Check logs
docker logs ai-secure-sdlc-backend

# Verify environment variables
echo $MONGO_URI
echo $GITHUB_TOKEN
```

#### Rate Limiting Too Strict

Edit `RATE_LIMIT_MAX` in `.env`:
```env
RATE_LIMIT_MAX=500        # Increase from default 100
RATE_LIMIT_WINDOW_MS=900000  # 15 minutes
```

### Frontend Issues

#### Frontend Can't Connect to Backend

```bash
# Check VITE_API_BASE_URL
echo $VITE_API_BASE_URL

# Should point to backend URL
# Local: http://localhost:4000
# Production: https://api.your-domain.com

# Test from frontend
curl http://localhost:4000/health
```

#### Port 5173 Already in Use

```bash
# Kill process
lsof -i :5173
kill -9 <PID>

# Or use different port
npm run dev -- --port 5174
```

#### Components Not Rendering

Check browser console for errors:
- Missing dependencies (recharts, axios, react-router-dom)
- API errors (check Network tab)
- CSS/Tailwind issues

### GitHub Webhook Issues

#### Webhook Not Triggering

1. Check GitHub webhook delivery logs
2. Verify URL is publicly accessible
3. Confirm secret matches
4. Check server logs for errors

```bash
# View backend logs
docker logs ai-secure-sdlc-backend -f

# Look for webhook errors
grep -i "webhook\|signature" logs.txt
```

#### Signature Verification Failed

```typescript
// Debug signature in backend
console.log("Expected secret:", process.env.GITHUB_WEBHOOK_SECRET);
console.log("Received header:", req.headers["x-hub-signature-256"]);

// Verify manual test
const crypto = require("crypto");
const payload = "test payload";
const secret = "your-secret";
const hash = crypto.createHmac("sha256", secret).update(payload).digest("hex");
console.log(`sha256=${hash}`);
```

### AI Service Issues

#### API Key Invalid/Expired

```bash
# Test OpenAI
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY"

# Test Anthropic
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY"
```

#### AI Review Slow/Timing Out

- Increase timeout in `aiService.ts`
- Check LLM API status
- Reduce batch size for processing findings
- Use cheaper model (GPT-3.5 instead of GPT-4)

#### High API Costs

Optimization strategies:
- Cache AI review results
- Batch multiple findings in one request
- Use cheaper models
- Implement deduplication
- Set up usage alerts

### Database Issues

#### Disk Space Low

```bash
# Check MongoDB disk usage
docker exec ai-secure-sdlc-db du -sh /data/db

# Archive old scans (move to cold storage)
db.scans.deleteMany({ createdAt: { $lt: new Date("2023-01-01") } })
```

#### Slow Queries

```javascript
// Check query performance
db.scans.find().explain("executionStats")

// Add missing indexes
db.scans.createIndex({ repositoryId: 1, prNumber: 1, commitSha: 1 })
db.findings.createIndex({ scanId: 1, severity: 1 })
```

#### Connection Pool Exhausted

Increase connection pool in `MONGO_URI`:
```
mongodb://user:pass@host:27017/db?maxPoolSize=50
```

### Performance Issues

#### High CPU Usage

```bash
# Check what's using CPU
docker stats ai-secure-sdlc-backend

# Profile with top
docker exec ai-secure-sdlc-backend top -b -n 1

# Reduce number of parallel AI reviews
# Edit webhookController.ts: use sequential instead of parallel
```

#### High Memory Usage

```bash
# Check memory
docker stats ai-secure-sdlc-backend

# Reduce in-memory cache
# Implement garbage collection in code
# Monitor for memory leaks
```

#### Slow Response Times

- Add database indexes
- Enable caching
- Use pagination for large result sets
- Optimize AI prompt (reduce tokens)
- Profile with `npm profile`

### Monitoring & Logging

#### Set Up Structured Logging

```typescript
// Use winston or pino
import winston from "winston";

const logger = winston.createLogger({
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: "error.log", level: "error" }),
    new winston.transports.File({ filename: "combined.log" })
  ]
});

logger.info("Scan initiated", { scanId, prNumber });
logger.error("AI review failed", { error: err.message });
```

#### Monitor Key Metrics

- API response times
- Database query times
- AI API costs
- Error rates
- Webhook delivery success rate

```bash
# Basic monitoring with curl
while true; do
  curl -s http://localhost:4000/health | jq .
  sleep 10
done
```

#### Set Up Alerting

```bash
# Example: Alert on high error rate
curl -X POST https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
  -d '{"text":"API errors: 5% in last 5 minutes"}'
```

---

## Backup & Recovery

### MongoDB Backups

```bash
# Manual backup
docker exec ai-secure-sdlc-db mongodump \
  --out /backup/$(date +%Y%m%d) \
  -u admin -p admin --authenticationDatabase admin

# Automated backup (cron)
0 2 * * * docker exec ai-secure-sdlc-db mongodump --out /backup/$(date +\%Y\%m\%d)

# Restore from backup
docker exec ai-secure-sdlc-db mongorestore \
  /backup/20240115 \
  -u admin -p admin --authenticationDatabase admin
```

### Configuration Backups

```bash
# Backup .env file
cp .env .env.backup.$(date +%Y%m%d)

# Store in secure location (not Git!)
# Use GitHub Secrets or secrets management tool
```

### Database Snapshots (AWS RDS)

```bash
# Create snapshot
aws rds create-db-snapshot \
  --db-instance-identifier ai-secure-mongodb \
  --db-snapshot-identifier ai-secure-backup-20240115

# Restore from snapshot
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier ai-secure-mongodb-restored \
  --db-snapshot-identifier ai-secure-backup-20240115
```

---

## Security Hardening

### HTTPS/TLS

```bash
# Generate self-signed cert (development)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365

# Use Let's Encrypt (production)
certbot certonly --standalone -d your-domain.com
```

### Firewall Rules

```bash
# Allow only necessary ports
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 80/tcp    # HTTP
sudo ufw enable

# Restrict database access
# MongoDB should only be accessible from backend
# Use VPC security groups / network policies
```

### Secret Management

```bash
# Use environment variable manager
# AWS Secrets Manager
aws secretsmanager create-secret \
  --name ai-secure/github-token \
  --secret-string "ghp_..."

# HashiCorp Vault
vault kv put secret/ai-secure github_token="ghp_..."

# GitHub Secrets (for Actions)
# Settings → Secrets and variables → Actions
```

### Regular Updates

```bash
# Update dependencies
npm update

# Check for vulnerabilities
npm audit
npm audit fix

# Update base images
docker pull node:20-alpine
docker pull mongo:7.0
docker pull nginx:1.25-alpine
```

---

## Support & Resources

- **Documentation**: See README.md, DEVELOPMENT.md, API.md
- **GitHub Issues**: Report bugs and request features
- **Status Page**: Monitor service uptime
- **Email**: support@your-domain.com
