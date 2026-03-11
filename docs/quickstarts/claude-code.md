# Claude Code Quickstart

Use ShieldCortex when you want Claude Code to remember important decisions, explain recall, and keep memory writes protected.

## Install

```bash
npm install -g shieldcortex
shieldcortex quickstart claude
```

Then restart Claude Code.

## Verify

```bash
shieldcortex doctor
shieldcortex dashboard
```

In the dashboard, start with:

- `Recall` to test what Claude would retrieve
- `Review` to suppress stale or noisy memories
- `Capture` to inspect what got stored recently

## Best fit

Choose this path if you want:

- durable local memory
- recall explanations
- contradiction-aware memory review
- memory poisoning defence on writes

