# Release checklist — pending ship-time items

This repo has no standing release checklist. This file holds items that must
be done when a specific change ships, not before. Tick and remove each item
in the release PR that ships its change.

## #853 (PR #959) — self-protection floor is always-block

Do these only in the release that ships #853. Until then the site's
"is held too" wording matches the released behaviour, so leave it alone.

- [ ] Site (shieldcortex.ai): change the self-protection line "A call it
      recognises as switching itself off … is held too" to "… is refused too".
      **Site deployment requires Michael's sign-off.**
- [ ] `docs/CLAIMS-PROOF.md` row 10b: remove the "(site wording predates
      #853)" note once the site says "is refused too".
