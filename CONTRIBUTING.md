# Contributing

Use Python 3.10+ and install `python -m pip install -e ".[dev]"`. Run `ruff check .`, `ruff format --check .`, `mypy src/osintmaster`, `pytest` and `python -m build` before opening a pull request.

Add sites to `src/osintmaster/data/sites.json` with an HTTPS profile URL, reliable absence status and profile-specific positive markers. Explain how false positives were checked. Keep requests conservative and add mocked tests; CI must never depend on a live social-media site. Never commit API keys, session cookies or real user reports.

For changes to scoring, state the weight and include examples where usernames match but identities cannot be inferred. Keep the report schema backwards compatible within a minor release when possible.
