# 03: Refutation-first verifier prompt

**What to build:** The verify prompt is rewritten from "rate each finding's confidence" to "assume every finding is wrong": the verifier's primary job is to hunt — using its read-only tools — for the sanitizer, parameterization, allowlist, dead path, or test-only caller that proves each finding safe. Findings it fails to refute are *confirmed*; the rest are Refuted Findings. Verdicts keep the existing confidence/exploitable axes and gain the cited evidence required for the refutation reason. Handles the `unsubstantiated` tag if present in the findings payload (treats it as extra-scrutiny), and works fine without it. The prompt-hash change triggers the expected one-time full re-verification of cached verdicts.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] New verify prompt frames refutation as the primary job; evidence citations required in the refutation reason
- [ ] Running verify with `--reverify` against a file with known false positives produces refutation-style verdicts with cited evidence
- [ ] Verdict schema remains compatible with existing confidence/exploitability report rendering
- [ ] Findings payload with an `unsubstantiated` tag is handled (extra scrutiny); payload without it also handled
- [ ] README's phase-3 section describes the refutation-first behavior
