# 05: Export allowlist candidates from refuted findings

**What to build:** A flag that turns the human-approval flow into a glance instead of a chore: it emits *candidate* suppression entries derived from Refuted Findings into the allowlist file, each marked with a candidate status (never auto-applied). Suppression remains human-confirmed only — candidates match nothing until a person approves them (flips status to confirmed); the report's audit trail distinguishes confirmed suppressions from still-candidate ones. This preserves the ADR's rule that machine refutations are reported, never silently allowlisted.

**Blocked by:** 04 (refuted re-bucketing — the refuted findings and their evidence must flow through the report first).

**Status:** ready-for-agent

- [ ] Flag exports candidate suppression entries from refuted findings (scanner, file, line, reason) into the allowlist file
- [ ] Candidate entries never suppress anything until approved (status flipped to confirmed by a human)
- [ ] Report's suppressed-findings audit trail separates confirmed suppressions from pending candidates
- [ ] Re-export is idempotent: an already-candidate or already-confirmed finding is not duplicated
- [ ] Tests cover export, idempotency, and the candidate-matches-nothing rule
