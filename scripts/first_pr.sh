#!/usr/bin/env bash
# 初回 PR: uBlacklist.txt (常設ルールのみ) を nightly/ ブランチで push し PR を作る。
# トークンは ~/.hermes/.env から読み、argv・stdout には出さない。
set -euo pipefail
ENV_FILE="${HERMES_ENV:-$HOME/.hermes/.env}"
[[ -f "$ENV_FILE" ]] && { set -a; . "$ENV_FILE"; set +a; }
: "${GITHUB_TOKEN:?GITHUB_TOKEN is not set}"

REPO_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
BRANCH="${2:-nightly/2026-09-24}"
BASE="${3:-main}"
OWNER_REPO="picaresq-tuat/ublacklist-scam-stores-jp"

cd "$REPO_DIR"

# トークンが .git/config に書かれていないことを先に検査 (書き込み事故の検知)
if git config --local --get-regexp '^credential' | grep -q "$GITHUB_TOKEN"; then
  echo "FATAL: token is stored in .git/config" >&2
  exit 1
fi
echo "precheck: token not in .git/config"

if git show-ref --verify --quiet "refs/heads/$BRANCH"; then
  git checkout "$BRANCH"
else
  git checkout -b "$BRANCH"
fi
git add -- uBlacklist.txt
if git diff --cached --quiet; then
  echo "no changes to commit"
else
  git commit -m "nightly 2026-09-24: uBlacklist.txt bootstrap (permanent rules)"
fi
git push -u origin "$BRANCH"

BODY=$(cat <<'EOF'
## nightly 2026-09-24 (bootstrap)

初回 PR です。以後この夜間ジョブが `uBlacklist.txt` を更新します。

- 追加: 0 件 (常設正規表現のみ)
- 削除 (失効): 0 件

### 常設正規表現
- `/https?:\/\/.*[\.\-](com|net|org)[\.\-][a-z]{2}\/.*/`
- `/https?:\/\/.*\.co\/.*/`
- `/https?:\/\/(?:[a-z0-9-]+\.)*xn--[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,8}\/.*/`

生成: `scam_hunter` (自動)。**人手承認後に `git merge --no-ff`** で取り込みます。
EOF
)

PAYLOAD=$(python3 - "$BRANCH" "$BASE" "$BODY" <<'PY'
import json, sys
head, base, body = sys.argv[1], sys.argv[2], sys.argv[3]
print(json.dumps({"title": "nightly: 2026-09-24 (bootstrap)", "body": body,
                  "head": head, "base": base, "draft": False}))
PY
)

HTTP=$(curl -s -o /tmp/pr_resp.json -w '%{http_code}' -X POST \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  -H 'User-Agent: scam-hunter' \
  -H 'Content-Type: application/json' \
  https://api.github.com/repos/$OWNER_REPO/pulls \
  --data-binary "$PAYLOAD")
echo "PR create HTTP $HTTP"
python3 - <<'PY'
import json
d = json.load(open('/tmp/pr_resp.json'))
if 'number' in d:
    print(f"PR #{d['number']}: {d['html_url']}")
else:
    print("err:", d.get('message'), d.get('errors'))
PY
