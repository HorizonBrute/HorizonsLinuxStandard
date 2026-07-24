---
type: Playbook
title: Standing up a new repo to the public-repo standard
description: Runbook for bringing a repo generated from the project template up to the public-repo standard — settings, topics, branch ruleset, signed commits, docs site.
tags: [github, repo-setup, runbook, template]
status: stable
---

# Standing up a new repo to the Horizon public-repo standard

This is the end-to-end runbook for taking a repo generated from this template and
bringing it up to the Horizon public-repo standard by hand. It captures the exact
process — settings, topics, branch ruleset, signed commits, and an optional docs
site — so anyone basing a project off this template can reproduce the whole setup.

GitHub's "generate from template" copies **files only** — not topics, rulesets,
security settings, discussions, or merge policy. Everything below applies the rest.

Most of steps 1–3 are automated by `.github/apply-standard-settings.sh`. The manual
`gh api` commands are given alongside each step as the fallback and as the
explanation of what the script does.

Prerequisites: `gh` installed and authenticated (`gh auth status`), and — for the
security features and the ruleset — the repo must be **public** or on **GitHub Pro /
Advanced Security**. On a private free repo the security and ruleset steps fail with
a clear error; enable them once the repo is public.

---

## 0. Create the repo and make it public

Create a new repo from this template (GitHub UI: **Use this template → Create a new
repository**, or `gh repo create <owner>/<repo> --template HorizonBrute/Horizon_public_open_use_project`).

Then make it public — the secret-scanning and ruleset steps below require it (or
GitHub Pro):

```bash
gh repo edit <owner>/<repo> --visibility public --accept-visibility-change-consequences
```

Clone it and `cd` in before running anything else.

---

## 1. Apply the standard settings (fast path)

Run the bundled script — it does sections A–C below in one shot:

```bash
./.github/apply-standard-settings.sh <owner>/<repo>
```

It applies:

- **General settings** — discussions on, auto update-branch on, web commit signoff
  required.
- **Topics** — a default set (see step 2 — change these to fit your project).
- **Secret scanning + push protection** — needs a public repo or GHAS; skipped with
  a notice otherwise.
- **Branch protection ruleset** — `Main_Dev_Protection` on `main` + `dev`; needs a
  public repo or GitHub Pro; skipped with a notice otherwise.

If you'd rather run the pieces by hand, or need to understand what the script does,
each section is below.

### A. General settings

```bash
gh api -X PATCH repos/<owner>/<repo> \
  -F has_discussions=true \
  -F allow_update_branch=true \
  -F web_commit_signoff_required=true
```

- `has_discussions=true` — enable the Discussions tab.
- `allow_update_branch=true` — let PR authors update their branch from base.
- `web_commit_signoff_required=true` — require a sign-off on commits made via the web UI.

Merge methods (squash + merge + rebase) are all enabled by GitHub default — leave
them as-is.

### B. Secret scanning + push protection

```bash
gh api -X PATCH repos/<owner>/<repo> \
  -f 'security_and_analysis[secret_scanning][status]=enabled' \
  -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'
```

**Public repos only** (or private with GitHub Advanced Security). On a private free
repo this returns HTTP 422 "not available" — that's expected; enable it once the repo
is public.

### C. Branch protection ruleset

```bash
gh api -X POST repos/<owner>/<repo>/rulesets --input ruleset.json
```

Where `ruleset.json` is (use `Master_Dev_Protection` and `refs/heads/master` when the
default branch is `master`):

```json
{
  "name": "Main_Dev_Protection",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/heads/main","refs/heads/dev"], "exclude": [] } },
  "rules": [
    {"type":"deletion"},{"type":"non_fast_forward"},{"type":"update"},{"type":"creation"},
    {"type":"required_linear_history"},{"type":"required_signatures"},
    {"type":"pull_request","parameters":{
      "required_approving_review_count":1,"dismiss_stale_reviews_on_push":true,
      "required_reviewers":[],"require_code_owner_review":false,
      "require_last_push_approval":true,"required_review_thread_resolution":false,
      "allowed_merge_methods":["merge","squash","rebase"]}}
  ],
  "bypass_actors": [ {"actor_id":5,"actor_type":"RepositoryRole","bypass_mode":"always"} ]
}
```

What each rule does:

- `deletion` — block deleting the protected branches.
- `non_fast_forward` — block force-pushes.
- `update` / `creation` — govern updates to and creation of the matched branches.
- `required_linear_history` — no merge commits on the branch; rebase/squash only.
- `required_signatures` — every commit must be signed (see step 3).
- `pull_request` — changes must land via PR with 1 approving review; stale reviews
  are dismissed on new pushes; the last push must be approved.
- `bypass_actors` — `RepositoryRole` `actor_id 5` (admin/owner) may bypass with
  `always`, so the owner can push directly when needed. Sign anyway (step 3).

**Public repo or GitHub Pro only.** On a private free repo the POST returns HTTP 403
"Upgrade to GitHub Pro or make this repository public" — apply it once public.

---

## 2. Set project-appropriate topics

Topics should describe **your** project's domain — don't blindly copy the template's
defaults. Lowercase-hyphenated, max 20.

```bash
gh api -X PUT repos/<owner>/<repo>/topics \
  -f names[]=<topic-1> -f names[]=<topic-2> -f names[]=<topic-3>
```

For example: a CLI tool might use `command-line-tool`, `developer-tools`, `python`; a
data project might use `data-pipeline`, `etl`, `analytics`. Pick what a person
searching GitHub for your project would actually type.

---

## 3. One-time developer GPG signing setup

The standard sets `web_commit_signoff_required=true` and the ruleset requires signed
commits, so contributors must sign. The owner has an admin bypass but should sign as a
matter of course. Each developer does this once on their machine.

1. **Have or create a GPG key** (RSA 4096, tied to your GitHub email):

   ```bash
   gpg --full-generate-key
   gpg --list-secret-keys --keyid-format=long
   ```

   Note the key fingerprint (`<FPR>`) from the listing.

2. **Configure git globally:**

   ```bash
   git config --global user.signingkey <FPR>
   git config --global commit.gpgsign true
   git config --global tag.gpgsign true
   ```

3. **Register the public key on GitHub.** Export it:

   ```bash
   gpg --armor --export <FPR>
   ```

   Paste it at <https://github.com/settings/gpg/new>. Or via the API (needs the
   `admin:gpg_key` token scope):

   ```bash
   gh auth refresh -h github.com -s admin:gpg_key
   gh api user/gpg_keys -f armored_public_key="$(gpg --armor --export <FPR>)"
   ```

4. **Verify:**

   ```bash
   git commit -S -m test
   git log --show-signature -1
   ```

   You should see "Good signature", and on GitHub the commit shows **Verified**.

---

## 4. Optional: GitHub Pages docs site

If the project ships docs, stand up an mkdocs-material site published by GitHub
Actions. Full guide: [docs/setting-up-a-github-docs-site.md](docs/setting-up-a-github-docs-site.md).

---

## 5. Verification checklist

- Settings applied — `gh api repos/<owner>/<repo> --jq '{has_discussions, allow_update_branch, web_commit_signoff_required}'` returns all `true`.
- Secret scanning on (public repos) — `gh api repos/<owner>/<repo> --jq '.security_and_analysis'`.
- Topics set — `gh api repos/<owner>/<repo>/topics --jq '.names'`.
- Ruleset present — `gh api repos/<owner>/<repo>/rulesets --jq '.[].name'` lists `Main_Dev_Protection`.
- A signed commit shows **Verified** on GitHub.
- If Pages is enabled — the site returns HTTP 200 (`curl -sI https://<owner>.github.io/<repo>/ | head -1`).
