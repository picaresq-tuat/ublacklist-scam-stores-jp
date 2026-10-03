#!/usr/bin/env bash
# このリポジトリ (スクリプトの 1 つ上) にのみ credential helper を設定する。
# トークン値は .git/config に書かない (実行時に env から読むヘルパ文字列のみ)。
set -euo pipefail
REPO="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
git -C "$REPO" config --local user.name "scam-hunter"
git -C "$REPO" config --local user.email "scam-hunter@localhost"
git -C "$REPO" config --local credential.helper '!f(){ printf "%s\n" "username=x-access-token"; printf "%s\n" "password=${GITHUB_TOKEN}"; }; f'
echo "configured: $REPO"
git -C "$REPO" config --local --get-regexp '^(user|credential)\.' | sed "s/^credential.helper .*/credential.helper [REDACTED-FORMAT]/"
