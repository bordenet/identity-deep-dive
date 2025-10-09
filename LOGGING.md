# Structured Logging Guide

## Overview

All projects use [zerolog](https://github.com/rs/zerolog) for structured JSON logging with timestamps. Logs are written to stdout in JSON format, making them easy to parse and aggregate.

## Log Format

Example log output:
```json
{
  "level": "info",
  "service": "oauth2-oidc-server",
  "timestamp": "2025-10-09T10:15:30.123456789Z",
  "message": "Server starting",
  "addr": ":8080",
  "issuer": "http://localhost:8080",
  "discovery": "http://localhost:8080/.well-known/openid-configuration"
}
```

### Standard Fields
- **level**: Log level (debug, info, warn, error, fatal)
- **service**: Service name (identifies which project generated the log)
- **timestamp**: ISO8601 timestamp with nanosecond precision
- **message**: Human-readable log message
- **Additional fields**: Context-specific structured data

## Configuration

### Log Level

Set via `LOG_LEVEL` environment variable:
```bash
export LOG_LEVEL=debug  # debug, info, warn, error
```

Default: `info`

### Project 1: OAuth2/OIDC Server
```bash
cd project-1-oauth2-oidc-demo
LOG_LEVEL=debug go run cmd/server/main.go
```

### Project 2: Security Scanner
```bash
cd project-2-identity-security-scanner
LOG_LEVEL=info ./bin/scanner scan --config examples/vulnerable-config.yaml
```

### Project 4: Session Management
```bash
cd project-4-session-management
LOG_LEVEL=debug go run cmd/server/main.go
```

## Free Tier Log Storage Options

### 1. [Grafana Cloud (Loki)](https://grafana.com/products/cloud/logs/) - RECOMMENDED

**Why**: Best free tier, easy setup, excellent querying

**Free Tier**:
- 50 GB logs/month
- 14-day retention
- 3 users
- Full Grafana dashboard integration

**Setup**:
```bash
# Install Promtail (log shipper)
brew install promtail

# Configure promtail.yaml
cat > promtail.yaml <<EOF
server:
  http_listen_port: 9080

positions:
  filename: /tmp/positions.yaml

clients:
  - url: https://<YOUR-LOKI-URL>/loki/api/v1/push
    basic_auth:
      username: <YOUR-USERNAME>
      password: <YOUR-API-KEY>

scrape_configs:
  - job_name: identity-projects
    static_configs:
      - targets:
          - localhost
        labels:
          job: oauth2-server
          __path__: /tmp/oauth2-server.log
EOF

# Run your app and pipe logs to file
go run cmd/server/main.go 2>&1 | tee /tmp/oauth2-server.log

# Start Promtail
promtail -config.file=promtail.yaml
```

**Query Examples** (in Grafana):
```logql
{job="oauth2-server"} |= "error"
{job="oauth2-server"} | json | level="error"
{service="oauth2-oidc-server"} | json | http_method="POST"
```

---

### 2. [Elastic Cloud (Free Tier)](https://www.elastic.co/cloud/elasticsearch-service/signup)

**Free Tier**:
- 14-day trial, then limited free tier
- 0.5 GB storage
- Single availability zone

**Setup**:
```bash
# Install Filebeat
brew tap elastic/tap
brew install elastic/tap/filebeat-full

# Configure filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /tmp/*.log
  json.keys_under_root: true
  json.add_error_key: true

output.elasticsearch:
  hosts: ["<YOUR-ELASTIC-CLOUD-URL>:9243"]
  api_key: "<YOUR-API-KEY>"

# Start filebeat
filebeat -e -c filebeat.yml
```

---

### 3. [Better Stack (Logtail)](https://betterstack.com/logs)

**Free Tier**:
- 1 GB logs/month
- 3-day retention
- 1 user

**Setup**:
```bash
# Stream logs directly via HTTP
go run cmd/server/main.go 2>&1 | \
  curl -X POST https://in.logs.betterstack.com/ \
    -H "Authorization: Bearer <YOUR-SOURCE-TOKEN>" \
    -H "Content-Type: application/json" \
    --data-binary @-
```

---

### 4. [Datadog Free Tier](https://www.datadoghq.com/)

**Free Tier**:
- 5 hosts
- 1-day retention
- Limited metrics

**Setup**:
```bash
# Install Datadog agent
DD_API_KEY=<YOUR-KEY> DD_SITE="datadoghq.com" bash -c "$(curl -L https://s3.amazonaws.com/dd-agent/scripts/install_mac_os.sh)"

# Configure log collection in /opt/datadog-agent/etc/datadog.yaml
logs_enabled: true

# Add log source in /opt/datadog-agent/etc/conf.d/identity-projects.d/conf.yaml
logs:
  - type: file
    path: /tmp/oauth2-server.log
    service: oauth2-oidc-server
    source: golang
    sourcecategory: identity

# Restart agent
sudo launchctl stop com.datadoghq.agent
sudo launchctl start com.datadoghq.agent
```

---

### 5. Local Development: [lnav](https://lnav.org/)

**Why**: Best local log viewer for JSON logs

**Setup**:
```bash
# Install lnav
brew install lnav

# View logs
go run cmd/server/main.go 2>&1 | tee /tmp/server.log
lnav /tmp/server.log

# Or pipe directly
go run cmd/server/main.go 2>&1 | lnav
```

**Features**:
- Real-time JSON parsing
- Syntax highlighting
- Filtering and searching
- SQL queries on logs
- No external service required

---

## Recommendation Matrix

| Use Case | Recommended Solution | Why |
|----------|---------------------|-----|
| **Learning/Development** | lnav | Free, local, no setup |
| **Demo/Portfolio** | Grafana Cloud (Loki) | Best free tier, professional UI |
| **Long-term retention** | Grafana Cloud (Loki) | 14-day retention, 50GB/month |
| **Team collaboration** | Better Stack | Good UI, team features |
| **Enterprise evaluation** | Datadog | Industry standard, robust |

---

## Best Practices

### 1. Always Log Structured Data
```go
// Good
log.Info().
    Str("client_id", clientID).
    Str("user_id", userID).
    Int("token_ttl_seconds", 900).
    Msg("Access token generated")

// Bad
log.Info().Msgf("Generated access token for client %s and user %s with TTL %d", clientID, userID, 900)
```

### 2. Use Appropriate Log Levels
- **Debug**: Detailed information for debugging (verbose)
- **Info**: General informational messages (normal operations)
- **Warn**: Warning messages (potential issues, degraded performance)
- **Error**: Error messages (failures, exceptions)
- **Fatal**: Fatal errors (application must exit)

### 3. Include Request Context
```go
reqLogger := logger.NewRequestLogger(requestID, r.Method, r.URL.Path)
reqLogger.Info().Msg("Handling authorization request")
```

### 4. Never Log Secrets
```go
// Good
log.Info().Str("client_id", clientID).Msg("Client authenticated")

// Bad - NEVER DO THIS
log.Info().Str("client_secret", secret).Msg("Client authenticated")
```

### 5. Add Trace IDs for Distributed Tracing
```go
log.Info().
    Str("request_id", requestID).
    Str("trace_id", traceID).
    Msg("Processing request")
```

---

## Example Queries

### Grafana Loki (LogQL)
```logql
# All errors
{service="oauth2-oidc-server"} | json | level="error"

# Authentication failures
{service="oauth2-oidc-server"} | json | message=~".*authentication.*failed.*"

# Slow requests (>1s)
{service="oauth2-oidc-server"} | json | duration_ms > 1000

# Requests by client
{service="oauth2-oidc-server"} | json | client_id="web-app"

# Rate of errors over time
rate({service="oauth2-oidc-server"} | json | level="error" [5m])
```

### lnav (SQL)
```sql
-- Count errors by message
SELECT message, count(*) as count
FROM log
WHERE level = 'error'
GROUP BY message
ORDER BY count DESC;

-- Average response time by endpoint
SELECT http_path, avg(duration_ms) as avg_duration_ms
FROM log
WHERE http_path IS NOT NULL
GROUP BY http_path;
```

---

## Integration with Observability

### Metrics (Prometheus)
Complement logs with metrics for quantitative data:
- Request rate
- Error rate
- Latency percentiles (p50, p95, p99)

### Traces (Jaeger/Zipkin)
Add distributed tracing for multi-service flows:
- OAuth2 authorization flow spans
- Token validation chains
- Database query traces

### Combined Approach
- **Logs**: What happened (events, errors, warnings)
- **Metrics**: How much/how fast (rates, durations, counts)
- **Traces**: Where time was spent (spans, dependencies)

---

## Next Steps

1. **Choose a log aggregation solution** from recommendations above
2. **Set up log shipping** using Promtail, Filebeat, or direct HTTP
3. **Create dashboards** for key metrics and error rates
4. **Set up alerts** for critical errors and anomalies
5. **Document runbooks** linking log queries to incident response

---

## References

- [zerolog Documentation](https://github.com/rs/zerolog)
- [Grafana Loki Documentation](https://grafana.com/docs/loki/latest/)
- [lnav Documentation](https://docs.lnav.org/)
- [The Twelve-Factor App: Logs](https://12factor.net/logs)
- [Google SRE Book: Monitoring Distributed Systems](https://sre.google/sre-book/monitoring-distributed-systems/)
