# Contributing to ShieldCortex

Thanks for taking the time to contribute. ShieldCortex guards agent memory, so a bug
here can quietly weaken someone else's security posture — we hold changes to a higher
bar than the size of the diff usually suggests.

## Ground Rules

- **Security issues never go in a public issue.** Follow [SECURITY.md](SECURITY.md)
  and email <security@drakonsystems.com> instead.
- **Open an issue before a large change.** For anything beyond a bug fix or a docs
  correction, describe the problem first so we can agree the approach before you
  spend the effort.
- **One concern per pull request.** A security fix should not carry a refactor along
  with it; they need different levels of scrutiny.

## Getting Set Up

Node 20 or later is required (CI runs 20 and 22).

```bash
git clone https://github.com/Drakon-Systems-Ltd/ShieldCortex.git
cd ShieldCortex
npm ci
npm run build:ts
npm test
```

For iterating without a rebuild each time, `npm run dev` runs the entry point through
`tsx`. The dashboard is a separate workspace: `cd dashboard && npm ci && npm run dev`.

## Before You Open a Pull Request

Run what CI runs, so the first failure you see is yours rather than the pipeline's:

```bash
npm run build:ts          # must compile clean
npm test                  # Jest suite
npm run test:dist         # no ESM-unsafe require() in dist
npm run guard:precision -- --planes   # Action Guard false-positive gate
```

If you touched the dashboard, also `cd dashboard && npm run lint && npm run build`.

A green suite is not the same as a working change. Run the real command against real
input and read what it actually printed before you call it done — most regressions we
have shipped passed their tests.

## Pull Request Expectations

- **Explain the failure, not just the fix.** Describe what breaks without your change
  and how you reproduced it. A fix for an unreproduced fault is a guess.
- **Include a regression test** that fails before your change and passes after. If you
  cannot write one, say why in the PR description.
- **Keep the diff the smallest one that fully solves the problem.** Opportunistic
  tidying makes a security review much harder.
- **Comments explain why, not what** — especially any non-obvious constraint that
  would tempt a future reader to "simplify" the code back into a bug.
- **Say what you did not do.** Parts you skipped, could not reach, or left unproven
  belong in the description. Silence about a gap reads as coverage.

## Areas That Need Extra Care

- **The Action Guard** — over-blocking is as damaging as under-blocking. Any change to
  its matching logic needs `npm run guard:precision` evidence in the PR.
- **Memory and claim scoping** — cross-agent contamination is the failure mode we care
  about most. Changes here need tests that prove isolation holds.
- **The host environment** — ShieldCortex must never break the agent or gateway it is
  installed into. Nothing in the install, repair, or hook paths may leave a host worse
  off than it found it.

## Reporting Bugs

Include the ShieldCortex version (`shieldcortex --version`), Node version, operating
system, the exact command you ran, and the full output. "It doesn't work" costs a
round trip we could both skip.

## Licence

By contributing you agree that your contributions are licensed under the MIT Licence,
the same terms that cover the rest of the project. See [LICENSE](LICENSE).
