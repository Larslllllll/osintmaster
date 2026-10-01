# Product roadmap and release gates

This tracks the staged work from the shared product plan. A stage is complete
only when its acceptance checks have been met; a source count by itself is not
evidence of reliable detection.

| Stage | Current implementation | Remaining gate |
| --- | --- | --- |
| P0 Reliability and release | Bounded requests, conservative statuses, tests, CI workflows, build and Trusted Publishing workflow | Review remote CI and configure the PyPI trusted publisher before tagging a release |
| P1 100 → 300 → 500+ sources | Seven default sources plus 139 opt-in public rules with dated positive and negative canaries; Sherlock and Maigret can contribute unverified candidates | Revalidate the catalogue continuously, then add further rules only after both controls pass; 300 and 500 validated sources are not reached |
| P2 Multiple targets | `case NAME TARGET...` investigates 2–20 typed seeds under one graph and budget | Broader target-specific providers and analyst-defined pivot queues |
| P3 Evidence graph | UUID entities, canonical keys, observations, evidence, typed relations, provider runs, pivots, SQLite and JSONL history | Richer graph queries and cross-run identity management |
| P4 Correlation 2.0 | Explained heuristic, contradictions, capped related name signals, weak pair suppression | Calibrate with labeled examples, account for base rates and provider dependence, and add analyst evaluation data |
| P5 Web app | Loopback workspace can launch and monitor bounded single-target or case hunts, browse saved runs; dashboard has history/diff and local hypothesis review | Granular annotation, a unified case workspace, and access control for any remote deployment |
| P6 Provider ecosystem | Entry-point username/search/event providers, declared cost/activity and bounded event HTTP context | Stable third-party contract, compatibility tests, provider versioning and catalogue maintenance workflow |

## Extended catalogue admission

The extended rules are adapted from a pinned [WhatsMyName data snapshot](https://github.com/WebBreacher/WhatsMyName/blob/062bcfe48df79fa618e96edc79dc9673f3fe5643/wmn-data.json).
The 139 packaged entries were selected from public GET-based rules with HTTPS
URLs, no authentication, and a declared positive control. Each had one live
positive match and one randomly generated negative match on 2026-10-01.
The checks require the configured HTTP code and response marker; ambiguous
responses stay `UNKNOWN`. Twenty-five rules use a separately rechecked HTTP
404 as the negative control where the upstream text marker drifted. They
return `PROBABLE`, not `CONFIRMED`.

Run `osintmaster health-catalog --start N --limit M --save result.json` to
recheck bounded slices. The dated result should be retained outside the
repository. A failed or inconclusive control requires investigation before a
rule is promoted or left in a production-facing catalogue. Canary results
cannot establish the accuracy of every possible username.

## Release gate

1. Run tests, lint, type checking, wheel/sdist build and metadata check locally.
2. Review the draft pull request and remote CI across supported Python versions.
3. Verify that the adapted catalogue and its CC BY-SA 4.0 attribution are in
   both distributions.
4. Configure PyPI Trusted Publishing for `.github/workflows/publish.yml` and
   the `pypi` GitHub environment.
5. Merge and publish a version-matched GitHub release tag after review.
