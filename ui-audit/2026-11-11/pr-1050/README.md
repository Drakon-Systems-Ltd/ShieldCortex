# PR #1050 — pure update renderer before/after capture

Captured 11 November 2026, with throwaway fixture versions and state.
Before: 6cfd7170b570ab2b7aef6aaf7f0626e0c10f7112.
After: d668e79357a020745edc0e949c4bdb082ca85f4b.

Desktop 1280×900 (80 terminal columns); mobile 390×844 (40 terminal columns).
Each image shows both the final update summary and the one-time notice when crossing 4.54.15. The ASCII renderer is used (non-TTY mode), no colors. Text files hold the raw renderer output. The browser supplies only a monospace terminal canvas; these are actual newly rendered output, not Jest snapshots.

Isolation: only the exact-head src/cli/update-summary.ts and src/cli/term-ui.ts were extracted and transpiled as standalone modules. No package entrypoint, update command, Guard, install, doctor, config, gateway, or test fixture was imported or exercised. Pure renderer executed in Node 24 permission mode, with filesystem reads allowed only inside the isolated capture directory, empty environment except PATH, no network/subprocess/filesystem-write grants. Fixture values match the existing calm-screen scenario: package updated, engine ready, plugin installed/restarted, skill/hook OK, Hermes absent, Guard off, protection unproven. Both update summary and renderGuardDefaultOffNotice used the same inputs at each head.

Chromium headless photographed local static HTML containing escaped raw renderer output, with a CSP denying resources/scripts. No server was started. All four screenshots were visually inspected: expected old enable suggestion present before and absent after, status command preserved, Guard remains 'off (the default)'. No clipping at these dimensions; long notice lines wrap within the mobile canvas.

Limitation: this proves the pure CLI presentation only, not end-to-end update/install behaviour or live Guard posture. Created after another maintainer had merged the PR; it is remediation evidence, not evidence that the pre-merge screenshot gate was met. Release remains held pending targeted independent acceptance and the separate guard-boundary release gate.
