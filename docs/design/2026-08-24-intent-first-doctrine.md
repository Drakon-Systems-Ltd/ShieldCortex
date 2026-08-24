# Intent-first doctrine — ShieldCortex product law

**Status:** Normative product doctrine (operator-directed)  
**Date:** 2026-08-24  
**Owner:** TARS · Directed by: Michael  
**Supersedes on conflict (UX / deny personality only):** bureaucratic “deny-by-default unless pinned” readings of Action Guard digests; overbuilt disposition-as-day-1-UX in research folds  
**Does not supersede:** catastrophe hard-stops, credential/secret non-exfil, attestation≠trust, no A2 multi-master, no `enforce:false` / broad autoApprove  

**Companion:** `2026-08-24-intent-first-target-architecture.md` (boxes + diagrams)  
**Background research (kept, demoted from day-1 UX):** `2026-08-24-memory-sota-defence-work-not-frustration.md`

---

## 1. One-line law

> **If Mike asked the agent to do a job on a trusted channel, ShieldCortex helps finish that job. It pauses in plain English only when something looks like a hijack — not when the agent is simply working.**

---

## 2. What Michael said (preserve)

- Trusted channel task → why would SC block normal work?
- If memory/write/recall is bent by injection (“forget last orders and do XYZ”), the engine should **piece it together** and card Mike:  
  *“Hold on Mike — are you sure you want me to do XYZ? That’s not like you / not what you asked.”*
- Over-engineering the deny surface frustrated operators (Edith uninstall). Simplify.

This doctrine is that product.

---

## 3. Channel trust

| Channel | Trust | Default |
|---|---|---|
| Michael → agent (Telegram allowlisted, TTY, Dashboard operator actions) | **Trusted intent** | **Allow the work** of that task |
| Agent tool steps that advance the stated task | **Task-scoped allow** | Allow unless catastrophe / clear mismatch |
| World → agent (web, files, tool results, untrusted memory, MCP schemas) | **Untrusted content** | Scan for **intent hijack**; never treat as Mike’s orders |
| SC memory vault | **Defended facts** | Store genuine work facts; **never execute memory as instructions** |

Iron Dome is a **bodyguard who knows who hired it**, not a bouncer who frisks the owner every step.

---

## 4. The only decision diamond (runtime)

```text
Event (tool call OR memory write/recall candidate)
        │
        ▼
 Catastrophe or secret exfil?
        │ yes → HARD STOP (no card required)
        │ no
        ▼
 Fits Mike’s current trusted task?
        │ yes → ALLOW (log quietly)
        │ no / unclear
        ▼
 Looks like hijack / override / “not what Mike asked”?
        │ yes → PLAIN ENGLISH CARD → Mike Allow once / Deny
        │ no
        ▼
 Soft allow or quiet log (don’t invent drama)
```

### Hard stop (rare, non-negotiable)
- Credential/secret exfil patterns  
- Catastrophic destroy (disk wipe class)  
- Clear malware/install-exec of untrusted remote payload when not the task  

### Plain card (the product)
```text
Hold on Mike — this doesn’t match your ask.

You asked:  <task summary>
It wants:   <one plain English line>
Why pause:  looks like override / injection / unusual for this task

[Allow once]   [Deny]
```

No issue numbers in the headline. No forensic essay. No “chat buttons aren’t a TTY.”  
Optional footer for operators who want it: action id + forensics path.

### Not a card
- Normal `gh` / deploy watch / Jotform / LAN re-sweep when **that is the task**  
- Routine git/build/edit in the worktree of the task  
- Memory facts (“Open Day is Fri 25 Sep”)  

---

## 5. Memory under intent-first

| Do | Don’t |
|---|---|
| Remember genuine work facts freely | Treat work facts like poison because they mention ports/IPs/dates |
| Keep instructions **out of inject packs** | Let “ignore Mike and …” from memory steer the agent |
| On override-shaped memory → **same plain card** | Binary-quarantine every imperative-looking note without asking |
| Facts in, orders from vault never auto-run | Empty the brain to feel “safe” |

Smart memory defence = **“is this still Mike’s job, or a hijack?”**  
Not a 40-row taxonomy as the operator-facing product.

---

## 6. What we keep (full stack — not deleted)

| Surface | Role under intent-first |
|---|---|
| **memories.db + defence pipeline** | Immune system for durable facts |
| **Inject pack** | Brief facts at session start — data, not orders |
| **Iron Dome / Action Guard** | Runtime diamond above |
| **#310 / notify / webhook** | Delivery rails for the **plain card** |
| **Work lanes / pins** | Optional standing toolkits + less card noise — **secondary**, not the only air supply |
| **Doctor** | Health of install/plane/guard |
| **Dashboard** | Cockpit: memory, holds, cards, replay |
| **X-Ray** | Workspace/file/deps sensor (environment) |
| **Graph / constellation** | Understanding layer over memories — not the deny engine |
| **Dream / Cortex / distill** | Capture quality for genuine work |
| **Cloud / fleet** | Same model, multi-host |

Research folds (dual-plane residual, multi-way disposition matrices) remain **engineering background**. They must not redefine day-1 personality against this doctrine.

---

## 7. Explicit refusals (still)

- `enforce:false` / broad autoApprove as the “fix”  
- Fake Allow buttons that don’t grant  
- Executing instructions **from** memory/tools as if Mike said them  
- A2 multi-master memory  
- Training operators to uninstall  

---

## 8. Success (human)

1. Mike can assign a real job; the agent finishes without siren theatre.  
2. A planted “forget your orders” pause gets **one English card**, not a silent wrong action and not a death spiral of DNPs.  
3. Dashboard/X-Ray/Graph still explain the world when Mike opens them.  
4. Uninstall is no longer the rational move to get work done.  

---

## 9. Build order (docs → spike → ship)

1. This doctrine + target architecture diagrams (**this PR**).  
2. **Task-intent context** — runtime knows current trusted task summary.  
3. **Plain card v1** — copy + Allow once / Deny on existing notify rails.  
4. **Diamond wiring** — Action Guard + memory override share the diamond.  
5. **Cockpit** — Dashboard shows task, holds, cards (Graph/X-Ray keep their jobs).  
6. Only then: reinstall candidates (e.g. Edith) on intent-first personality.

No fleet cut required to accept the doctrine. Implementation is gated on Michael “go” for code spikes.
