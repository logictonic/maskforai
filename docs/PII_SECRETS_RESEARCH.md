# PII and Secrets Filtering Research

## Sources

- **Presidio** (Microsoft): NER + regex, 500+ patterns, GDPR/HIPAA
- **Secrets-Patterns-DB** (mazen160): 1600+ regex, TruffleHog/Gitleaks format
- **TruffleHog**: 800+ secret types, validation against APIs
- **OpenRedaction**: 500+ tested patterns, self-hosted
- **detect-secrets** (Yelp): Pattern-based, pre-commit hooks

## PII Categories

| Category | Examples | Detection |
|----------|----------|-----------|
| Direct identifiers | Email, phone, SSN, credit card | Regex + format validation |
| Contextual | IP, MAC, device ID, customer ID | Regex |
| Quasi-identifiers | DOB, postcode, job title | Regex/NER |

## Pattern Priorities

1. **API keys/tokens** (high confidence) — specific prefixes
2. **Connection strings** — scheme://user:pass@
3. **Generic secrets** — KEY=value, password=
4. **PII** — email, phone, SSN, credit card
5. **Network identifiers** — IP, MAC (lower priority, more false positives)

## Implemented Patterns (mask-proxy)

### API Keys / Tokens
- Anthropic, OpenAI, GitHub, AWS, Stripe, Perplexity
- Google/Firebase (AIza prefix)
- OpenRouter, Slack (xoxb/p/a/r/s), Twilio (SK/AC/SI)
- SendGrid, DigitalOcean, HashiCorp Vault, NPM

### Connection Strings
- postgresql, postgres, redis, mongodb, amqp, amqps, mysql

### Generic
- SECRET_KEY=, API_KEY=, JWT_SECRET=, password=, Bearer, JWT, PEM keys

### PII
- Email, phone, SSN (US format), credit card (4×4 digits)
- IPv4 (valid dotted decimal), MAC address (XX:XX:XX:XX:XX:XX)

### Order of Application
Bearer before JWT. Specific API keys before generic. PII last.
