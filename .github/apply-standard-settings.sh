#!/usr/bin/env bash
#
# apply-standard-settings.sh — bring a repo up to the Horizon public-repo standard.
#
# GitHub's "generate from template" copies files only — NOT topics, rulesets,
# security settings, discussions, or merge policy. Run this once against a newly
# generated repo to apply all of that.
#
# Usage:   ./.github/apply-standard-settings.sh <owner>/<repo>
# Example: ./.github/apply-standard-settings.sh HorizonBrute/my-new-project
#
# Requires: gh (authenticated), the repo already created & PUBLIC
# (secret scanning + rulesets need a public repo or GitHub Pro/GHAS).

set -euo pipefail

REPO="${1:-}"
if [[ -z "$REPO" ]]; then
  echo "Usage: $0 <owner>/<repo>" >&2
  exit 1
fi

echo ">> Applying Horizon public-repo standard to: $REPO"

echo ">> [1/4] General settings (discussions, update-branch, commit signoff)"
gh api -X PATCH "repos/$REPO" \
  -F has_discussions=true \
  -F allow_update_branch=true \
  -F web_commit_signoff_required=true \
  --jq '{has_discussions, allow_update_branch, web_commit_signoff_required}'

echo ">> [2/4] Topics"
gh api -X PUT "repos/$REPO/topics" \
  -f names[]=agent-framework -f names[]=agent-loop-toolkit -f names[]=agent-loops \
  -f names[]=agent-orchestration -f names[]=agent-skills -f names[]=agentic-workflow \
  -f names[]=agents -f names[]=ai-agents -f names[]=ai-orchestration \
  -f names[]=multi-agent -f names[]=prompt-engineering -f names[]=workflow-automation \
  --jq '.names'

echo ">> [3/4] Secret scanning + push protection"
gh api -X PATCH "repos/$REPO" \
  -f 'security_and_analysis[secret_scanning][status]=enabled' \
  -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled' \
  --jq '.security_and_analysis | {secret_scanning: .secret_scanning.status, push_protection: .secret_scanning_push_protection.status}' \
  || echo "   (skipped — needs a public repo or GitHub Advanced Security)"

echo ">> [4/4] Branch protection ruleset (main + dev)"
gh api -X POST "repos/$REPO/rulesets" --input - <<'JSON' --jq '{id, name, enforcement, rules: [.rules[].type]}' \
  || echo "   (skipped — needs a public repo or GitHub Pro)"
{
  "name": "Main_Dev_Protection",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/heads/main","refs/heads/dev"], "exclude": [] } },
  "rules": [
    {"type":"deletion"},
    {"type":"non_fast_forward"},
    {"type":"update"},
    {"type":"creation"},
    {"type":"required_linear_history"},
    {"type":"required_signatures"},
    {"type":"pull_request","parameters":{
      "required_approving_review_count":1,
      "dismiss_stale_reviews_on_push":true,
      "required_reviewers":[],
      "require_code_owner_review":false,
      "require_last_push_approval":true,
      "required_review_thread_resolution":false,
      "allowed_merge_methods":["merge","squash","rebase"]
    }}
  ],
  "bypass_actors": [ {"actor_id":5,"actor_type":"RepositoryRole","bypass_mode":"always"} ]
}
JSON

echo ">> Done. Remaining manual steps (optional):"
echo "   - Enable GitHub Pages if the project ships docs."
echo "   - Adjust the license file if this project is not MIT."
