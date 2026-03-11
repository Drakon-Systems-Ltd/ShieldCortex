# MCP Agent Quickstart

Use ShieldCortex when you want an MCP-compatible memory and security layer that works across agents, not just one editor.

## Install

```bash
npm install -g shieldcortex
shieldcortex install
```

This sets up the local server and hooks for common MCP-driven coding agents.

## Verify

```bash
shieldcortex doctor
shieldcortex status
```

## If the agent runs on a server

For headless Linux hosts or always-on cloud boxes, connect the machine to ShieldCortex Cloud with the persistent worker:

```bash
shieldcortex license activate <team-key>
shieldcortex config --cloud-api-key <cloud-api-key>
shieldcortex config --cloud-enable
shieldcortex service install --headless
```

See [cloud-servers.md](cloud-servers.md) for the full verification flow.

## What you get

- durable local memory
- semantic recall
- recall explanations
- review queue
- memory poisoning defence
- optional cloud replica sync for team visibility

## Best workflow

After install, open:

```bash
shieldcortex dashboard
```

Start with `Recall` and `Review`, not the graph. That gives you the fastest path to trustworthy agent memory.
