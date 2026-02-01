# ShieldCortex Roadmap

## Phase 1: Sub-Agent Security (PRIORITY — Q1 2026)

**The problem:** AI agents spawn sub-agents that inherit full system access — filesystem, credentials, secrets, personal data. There is zero isolation. A compromised or misbehaving sub-agent can exfiltrate API keys, read private files, send emails, and push malicious code.

**What we're building:**

### 1.1 Agent Trust Scoring
Extend the existing trust scorer to cover agent-to-agent interactions:
- **Parent agents** get trust score based on source (user-spawned=0.9, cron-spawned=0.5, agent-spawned=0.3)
- **Sub-agents** inherit a decayed trust score from their parent (parent × 0.7)
- **Chain depth penalty** — each level of sub-agent spawning reduces trust further
- Trust scores determine what memory operations are allowed (read/write/delete)

### 1.2 Credential Isolation
- Sub-agents cannot access credential stores (1Password, env files, token files)
- Parent agent provisions scoped, time-limited tokens for specific tasks
- Memory firewall blocks any memory write containing credentials, tokens, or secrets
- Audit trail logs all credential access attempts by agent tier

### 1.3 Memory Access Control
- **Read ACLs** — sub-agents can only read memories they created or were explicitly granted
- **Write restrictions** — sub-agents write to a quarantine zone; parent agent approves promotion
- **Personal data fence** — memories tagged as personal/private are invisible to sub-agents
- **Sensitivity classifier** auto-tags on write; restricted memories never leak down the trust chain

### 1.4 Sub-Agent Audit Trail
- Every sub-agent action logged: shell commands, file reads/writes, memory operations
- Parent agent receives a security digest when sub-agent completes
- Anomaly detection: flag unexpected file access, credential reads, network calls
- Forensic replay: reconstruct exactly what a sub-agent did

### 1.5 Uninstall Protection (Enhancement)
- Sub-agents cannot remove or disable ShieldCortex
- Requires TTY confirmation from a human operator
- Any attempt to uninstall triggers an alert to the parent agent

## Phase 2: SaaS API MVP (Q1-Q2 2026)
- Hosted API on Fly.io (Hono + Postgres)
- API key authentication
- Cloud-hosted defence pipeline
- Dashboard with threat visualisation
- Waitlist → beta → launch

## Phase 3: Enterprise Features (Q2-Q3 2026)
- Multi-tenant isolation
- Compliance exports (SOC2, GDPR audit trails)
- Custom defence rules engine
- Webhook alerts (Slack, PagerDuty, email)
- SSO / SAML integration

## Phase 3.5: External Agent Monitoring (Q3 2026)
- Monitor third-party agent platforms (Moltbot, etc.)
- Detect compromised agents in the wild
- Threat intelligence feed
- Community-contributed threat signatures

## Phase 4: Agent Mesh Security (Q4 2026+)
- Multi-agent communication security
- Signed memory operations (cryptographic proof of origin)
- Cross-agent trust federation
- Zero-knowledge memory proofs — verify a memory exists without revealing content

---

*Last updated: 2026-02-01*
