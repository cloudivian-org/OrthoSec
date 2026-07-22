# Publishing OrthoSec

Both packages are release-ready. Publishing needs your registry tokens — the
commands below are all that's left. No CI required.

## PyPI (Python package `orthosec`)

```bash
# one-time: pip install build twine
python -m build                       # builds dist/*.whl and dist/*.tar.gz
python -m twine check dist/*          # validate metadata
python -m twine upload dist/*         # prompts for your PyPI token (or set TWINE_PASSWORD)
```

Then anyone can:

```bash
pip install orthosec            # core scanner (zero deps)
pip install "orthosec[intel]"   # + executive briefing / auto-fix (Anthropic / Azure)
```

Verify before upload: the wheel ships `orthosec/py.typed`, the `orthosec`
console entry point, and all detectors. `python -m build` here produces both
artifacts cleanly.

## npm (Node guard `@orthosec/guard`)

```bash
cd sdk/js
npm publish --access public      # scoped package → --access public is required
```

Then:

```bash
npm install @orthosec/guard
```

The package is pure ESM with bundled `.d.ts` types and zero dependencies;
`npm test` runs the node:test suite.

## Versioning

Bump `version` in `pyproject.toml` and `sdk/js/package.json` together, update
`CHANGELOG.md`, tag `vX.Y.Z`, then run the publish commands above.
