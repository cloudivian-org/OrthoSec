# Publishing OrthoSec

The recommended path is the **automated, signed release** below (Trusted Publishing /
OIDC — no token stored anywhere). Manual `twine upload` is kept as a fallback.

## Pre-publish checklist (verified for v0.13.0)

- [x] `python -m build` produces a clean wheel + sdist
- [x] `python -m twine check dist/*` → PASSED (both artifacts)
- [x] Wheel installs and the `orthosec` console script runs (`orthosec --version` → 0.13.0, 12 detectors, LLM01–10)
- [x] `requires-python >=3.9`; full test suite green (363); benchmark 104 cases, 100% / 0 FP
- [x] Version consistent: `pyproject.toml` 0.13.0, `orthosec/__init__.py` 0.13.0, `CHANGELOG.md` 0.13.0
- [ ] **You (one-time):** configure the PyPI trusted publisher (see below)
- [ ] **You:** cut tag `v0.13.0` + publish the GitHub Release → CI builds, signs, and uploads

## Signed release via CI (recommended)

`.github/workflows/release.yml` has two jobs:

- **publish-image** — builds and pushes the container to GHCR on any `v*` **tag push**.
- **publish-pypi** — runs only on a **published GitHub Release**: builds the sdist+wheel,
  attaches a **SLSA build-provenance attestation** and **PEP 740 attestations**, uploads
  the artifacts to the Release, and publishes to PyPI via **OIDC — no API token**.

So a bare tag ships the Docker image; publishing the GitHub Release ships PyPI.

### One-time: configure the PyPI trusted publisher

On pypi.org → project `orthosec` → Manage → Publishing → Add a new publisher (GitHub Actions):

- **Owner:** `cloudivian-org`  ·  **Repository:** `OrthoSec`
- **Workflow name:** `release.yml`  ·  **Environment name:** `pypi`

(`orthosec` already exists on PyPI, so add it as a publisher on the existing project — not
a "pending" publisher.)

### Cut the release

```bash
git tag v0.13.0 && git push origin v0.13.0        # -> GHCR image build
gh release create v0.13.0 --title "v0.13.0" --notes-file <(sed -n '/## \[0.13.0\]/,/## \[0.12.3\]/p' CHANGELOG.md)
# publishing the Release -> build + SLSA attest + OIDC publish to PyPI
```

Then anyone can:

```bash
pip install orthosec            # core scanner (zero deps)
pip install "orthosec[intel]"   # + executive briefing / auto-fix (Anthropic / Azure)
```

## Manual PyPI upload (fallback only)

Use only if the trusted publisher is not yet configured. Don't do both for the same
version — PyPI rejects duplicate uploads.

```bash
python -m build                       # builds dist/*.whl and dist/*.tar.gz
python -m twine check dist/*          # validate metadata
python -m twine upload dist/*         # prompts for your PyPI token (or set TWINE_PASSWORD)
```

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

Bump `version` in `pyproject.toml` and `orthosec/__init__.py` together (and
`sdk/js/package.json` for the Node guard), update `CHANGELOG.md`, then cut the
release as above.
