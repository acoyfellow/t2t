#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
PROFILE_FILE="$HOME/.alchemy/profiles/customer0/cloudflare.json"
export CLOUDFLARE_ACCOUNT_ID=$(node -p "JSON.parse(require('fs').readFileSync('$PROFILE_FILE','utf8')).values.accountId")
export CLOUDFLARE_API_TOKEN=$(node -p "JSON.parse(require('fs').readFileSync('$PROFILE_FILE','utf8')).values.access")
exec node_modules/.bin/alchemy "${1:-deploy}" --stage prod --yes --no-input
