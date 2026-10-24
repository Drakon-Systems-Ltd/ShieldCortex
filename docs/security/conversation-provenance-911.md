# Conversation UUID false-taint correction (#911)

A bare UUID is not evidence of a Heroku credential. The Heroku rule now requires a same-line Heroku identifier within 64 characters before the UUID. Explicit HEROKU_API_KEY assignments and nearby provider context remain detected; other provider detectors are unchanged.

Credential-only tool-response summaries remain threats for reporting and credential redaction, but do not establish instruction steering and therefore do not raise conversation session taint. Any additional instruction, injection, encoding, exfiltration or other threat layer retains the prior taint policy. This applies to credential-only findings at all confidence levels, not just low-confidence UUID matches.

The OpenClaw llm_input prompt is an unsegmented string and can include host framing and quoted conversation history. The supported event contract supplies no attested per-span origin. It is therefore labelled unknown rather than user. Structured user text blocks remain user; structured tool output remains tool_result. Neither textual OpenClaw markers nor XML-like wrappers establish host trust. Unknown content remains scanned; this change does not exempt host-looking strings or invent a trusted host label.

Limitation: genuine host framing that matches an instruction detector can still be detected and taint. Safely exempting such spans requires structural origin metadata from the host, not content matching. This patch does not change live posture, approval handling, owner trust, or the host event contract.
