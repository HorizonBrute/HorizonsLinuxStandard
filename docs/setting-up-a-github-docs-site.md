# Setting up a GitHub Pages docs site

This is the docs-site pattern for Horizon public repos: **mkdocs-material, built and
published to a `gh-pages` branch by GitHub Actions** on every push to the default
branch. It's two files plus a couple of one-time API calls.

---

## 1. `mkdocs.yml`

Put it at the repo root (simplest). `docs_dir` points at the folder holding your
markdown docs — the path is **relative to the `mkdocs.yml` location**.

```yaml
site_name: "Your Project Name"
docs_dir: docs
theme:
  name: material
  palette:
    scheme: slate
  features:
    - navigation.tabs
    - navigation.sections
    - search.suggest
    - search.highlight
nav:
  - Home: index.md
  - Some Page: "subdir/page.md"
```

Requirements to get right:

- The `docs_dir` must contain an `index.md` (or the `nav` Home entry must point at a
  file that exists).
- **Every** `nav` path must exist, or the build warns/fails.
- Nav paths are relative to `docs_dir`.

---

## 2. Validate locally before pushing

```bash
pip install mkdocs-material
mkdocs build
```

A clean `mkdocs build` (no warnings) means the Action will succeed. Fix any missing
files or broken nav paths it reports before you push.

---

## 3. `.github/workflows/docs.yml`

```yaml
name: Deploy Docs
on:
  push:
    branches:
      - main    # use your DEFAULT branch (e.g. master)
permissions:
  contents: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.x"
      - name: Install mkdocs-material
        run: pip install mkdocs-material
      - name: Deploy to GitHub Pages
        run: mkdocs gh-deploy --force
```

`mkdocs gh-deploy` builds the site and force-pushes the result to a `gh-pages`
branch. Set the `on.push.branches` value to your repo's actual default branch.

---

## 4. Enable Pages from the `gh-pages` branch

The `gh-pages` branch only exists after the workflow has run at least once, so push
the two files first and wait for the Action to finish:

```bash
gh run watch
```

Then point Pages at the branch (use `PUT` instead of `POST` if Pages already exists):

```bash
gh api -X POST repos/<owner>/<repo>/pages \
  -f 'source[branch]=gh-pages' \
  -f 'source[path]=/'
```

---

## 5. Set the repo homepage

Point the repo's homepage link at the published site:

```bash
gh api -X PATCH repos/<owner>/<repo> \
  -f homepage='https://<owner>.github.io/<repo>/'
```

Verify the site is live:

```bash
curl -sI https://<owner>.github.io/<repo>/ | head -1   # expect: HTTP/2 200
```

---

## Gotcha: keep intra-site links inside `docs_dir`

Markdown links written for browsing the repo on GitHub that point **outside**
`docs_dir` (e.g. `../README.md` or a file elsewhere in the tree) will **404** on the
built site — mkdocs only publishes what's under `docs_dir`. Keep links between pages
within the docs scope. If you need to reference an out-of-scope file, either copy it
into `docs_dir` or link to its absolute URL on GitHub.
