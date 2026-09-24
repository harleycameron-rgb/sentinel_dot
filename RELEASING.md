# Releasing sentinel_dot

The version lives in one place: `__version__` in `src/sentinel_dot/__init__.py`.

## Option A: manual upload (quickest first release)

1. Create accounts on [PyPI](https://pypi.org/account/register/) and [TestPyPI](https://test.pypi.org/account/register/), and turn on 2FA (required).
2. Create an API token for each (Account settings → API tokens, scope "Entire account" for the first upload, since the project doesn't exist yet).
3. Build and check:
   ```bash
   pip install -e ".[dev]"
   pytest -q && pytest -q -m network
   rm -rf dist && python -m build
   twine check --strict dist/*
   ```
4. Rehearse on TestPyPI:
   ```bash
   twine upload --repository testpypi dist/*        # username: __token__, password: the TestPyPI token
   python -m venv /tmp/t && /tmp/t/bin/pip install -i https://test.pypi.org/simple/ \
       --extra-index-url https://pypi.org/simple/ "sentinel_dot[all]"
   /tmp/t/bin/sentinel_dot --version
   ```
5. Publish for real:
   ```bash
   twine upload dist/*                              # PyPI token
   ```
6. After the first upload, replace the account-wide token with one scoped to the `sentinel_dot` project.

Never commit tokens. Store them in `~/.pypirc` (mode 600) or pass them via `TWINE_PASSWORD`.

## Option B: GitHub Actions + Trusted Publishing (recommended after that)

No tokens are stored anywhere. PyPI trusts this repository's workflow.

1. The repository is `harleycameron-rgb/sentinel_dot`, and `[project.urls]` is already filled in.
2. On PyPI → your project → Publishing → add a trusted publisher:
   owner `harleycameron-rgb`, repository `sentinel_dot`, workflow `publish.yml`, environment `pypi`.
   Do the same on TestPyPI with environment `testpypi`.
   (Before the first release you can use "pending publisher" from your account's Publishing page.)
3. In GitHub → Settings → Environments, create `pypi` and `testpypi`. Add yourself as a required reviewer on `pypi`.
4. Rehearse: Actions → publish → Run workflow → target `testpypi`.
5. Release:
   - bump `__version__`, move changelog notes under the new version, commit
   - `git tag v0.2.1 && git push --tags`
   - create a GitHub Release from the tag, which triggers publishing to PyPI

The workflow runs the tests, refuses to publish if the tag doesn't match `__version__`, builds, runs `twine check --strict`, then uploads.

## Checklist

- [ ] Tests pass (offline and `-m network`)
- [ ] `__version__` bumped, CHANGELOG updated with the date
- [ ] `twine check --strict dist/*` passes
- [ ] TestPyPI install works: `sentinel_dot --version`, `keygen --ed25519`, `anchor verify-proof`
- [ ] Tag `vX.Y.Z` matches `__version__`

PyPI versions are permanent: a deleted release's version number can never be reused. If a release is broken, fix it and publish the next patch version.
