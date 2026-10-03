#!/usr/bin/env bash
# GitHub 認証つき git ラッパ。トークンは ~/.hermes/.env から読み、argv・ログに出さない。
set -euo pipefail
ENV_FILE="${HERMES_ENV:-$HOME/.hermes/.env}"
if [[ -f "$ENV_FILE" ]]; then
  set -a; # shellcheck disable=SC1090
  . "$ENV_FILE"; set +a
fi
: "${GITHUB_TOKEN:?GITHUB_TOKEN is not set}"
HELPER='!f(){ printf "%s\n" "username=x-access-token"; printf "%s\n" "password=${GITHUB_TOKEN}"; }; f'
exec git -c credential.helper="$HELPER" "$@"
