# Changelog

## 0.3.0 — unreleased

- Add an opt-in 139-site extended catalogue with dated positive/negative controls, a bounded health command and clear data licensing.
- Investigate multiple typed seeds in one case graph and shared budget.
- Cap related handle/name correlation evidence and omit weak pairwise links from reports.
- Save local analyst decisions and notes for hypothetical graph links in a guarded dashboard review page.
- Load enabled event-provider entry points in hunts and cases through the shared bounded context.
- Start and monitor bounded hunts and cases from a loopback-only browser workspace.
- Make the hunt graph evidence backed: UUID entities, canonical keys, separate observations and evidence, provider-run links, negative check states, and scored pivot suggestions.
- Persist normalized graph records in SQLite and JSONL; show observation history, provenance, and pivot priorities in the local dashboard.
- Accept international E.164 phone seeds and IDN domains; retain platform IDs from supported public profile APIs.
- Let opt-in Sherlock and Maigret adapters use their default site catalogues while retaining conservative candidate status and bounded subprocesses.
- Audit live profile checks; remove Reddit from built-in and external defaults after reproduced false leads, classify explicit Bluesky absence, and enforce streaming response limits.
- Render untrusted CLI fields as literal text and remove terminal control characters from displayed values.
- Preserve case-sensitive Hacker News handles through scans, hunts and report storage.
- Add transactional SQLite investigation history, run IDs, JSONL export, and cautious run comparison.
- Add an event-provider contract with declared inputs, outputs, cost and activity, plus a bounded shared HTTP context.
- Add Telegram public-preview checks that distinguish channels, groups and users where the page supports it; generic HTTP 200 pages do not count as matches.
- Show event provenance and provider activity in the local HTML dashboard.
- Add opt-in, dated provider health checks using supplied positive and negative canaries.
- Classify refused HTTP access as unresolved `BLOCKED` and retain explicit absence evidence.
- Report missing enabled external tools and malformed Maigret records as partial-scan errors.
- Browse prior SQLite runs in the local dashboard and open a snapshot by run ID.
- Compare adjacent saved runs in the dashboard with guarded HTML and JSON views.

## 0.2.0 — unreleased

- Add bounded `hunt` investigations with typed events, provenance, recursive known-profile pivots and entity graph export.
- Add a local interactive dashboard with filtering, public evidence and clickable graph nodes.
- Use exact public API checks for six built-in sites, add DEV Community, Hacker News and Bluesky, and harden page redirects.
- Add negative evidence and status-aware correlation, plus target and graph tests.

## 0.1.0 — unreleased

- Initial registry-driven public username scanner with bounded asynchronous requests.
- Explainable correlation, JSON and standalone HTML reports.
- Local metadata, image hashes, optional Sherlock and Maigret adapters.
- CLI, configuration, doctor checks, tests and release workflows.
