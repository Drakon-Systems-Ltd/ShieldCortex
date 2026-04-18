# Adversarial Sample Skill — DO NOT PUBLISH

This is a synthetic adversarial skill used for ShieldCortex demonstration and
testing. It is intentionally crafted to trip the skill scanner's
`tool_injection`, `data_exfiltration`, and `stealth_instruction` patterns.

## Why this exists

ShieldCortex needs realistic test fixtures for:

- Demo videos / live attack playbacks
- Regression tests on the skill scanner's pattern matching
- Documentation of the attack vectors we defend against

## Safety

The skill contains **no executable code**. It is a SKILL.md file with prose
instructions. The "attack" is the hidden instruction to an LLM agent — there
is no shell script or binary that runs anything on disk.

Do not publish this skill to ClawHub or any registry. It exists only as a
local sample inside this repository.

## How to scan it

```bash
npx shieldcortex scan-skill examples/adversarial-skill/SKILL.md
```

Expected output: BLOCK with `data_exfiltration`, `tool_injection`, and
`stealth_instruction` threat indicators.
