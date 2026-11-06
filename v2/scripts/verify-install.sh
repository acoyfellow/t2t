#!/bin/bash
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/.." && pwd)"
FAIL=0
pass() { printf 'PASS %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; FAIL=1; }

[ -x "$ROOT/scripts/install.sh" ] && pass "install.sh is executable" || fail "install.sh missing or not executable"
[ -x "$ROOT/scripts/verify-install.sh" ] && pass "verify-install.sh is executable" || fail "verify-install.sh missing"
bash -n "$ROOT/scripts/install.sh" && pass "install.sh syntax ok" || fail "install.sh syntax"

grep -q "One-time setup" "$REPO_ROOT/README.md" && pass "README documents .secrets setup" || fail "README missing .secrets setup"
grep -q "scripts/deploy.sh" "$REPO_ROOT/README.md" && pass "README uses scripts/deploy.sh" || fail "README deploy step wrong"
grep -q "dev.coey.t2t-ui" "$REPO_ROOT/README.md" && pass "README documents UI LaunchAgent" || fail "README missing LaunchAgent"
! grep -q "npm run ui &" "$REPO_ROOT/README.md" && pass "README no longer tells users to background vite" || fail "README still backgrounds vite"

tmp=$(mktemp -d)
mkdir -p "$tmp/v2"
(cd "$ROOT" && git ls-files -co --exclude-standard -- . ':!node_modules' | while IFS= read -r f; do mkdir -p "$tmp/v2/$(dirname "$f")"; cp "$f" "$tmp/v2/$f" 2>/dev/null || true; done)
(cd "$tmp/v2" && ./scripts/install.sh --check >/dev/null 2>&1) && pass "install.sh --check runs in clean copy" || fail "install.sh --check fails in clean copy"
out=$(cd "$tmp/v2" && ./scripts/install.sh --check 2>&1); case "$out" in *"Missing"*"check-only"*) pass "clean copy reports missing prerequisites";; *) fail "clean copy does not report missing prerequisites";; esac
rm -rf "$tmp"

if curl -s -m 3 -o /dev/null -w '%{http_code}' localhost:5197/ 2>/dev/null | grep -q 200; then pass "UI on :5197 (200)"; else printf 'SKIP UI on :5197 (app not running)\n'; fi
if curl -s -m 3 localhost:5198/state 2>/dev/null | grep -q '"overlayVisible"'; then pass "shell on :5198 (/state ok)"; else printf 'SKIP shell on :5198 (app not running)\n'; fi

git -C "$REPO_ROOT" ls-files | grep -q 'secrets/' && fail ".secrets is tracked" || pass ".secrets not tracked"
git -C "$REPO_ROOT" status --short | grep -q '^\?\? .*\.secrets' && fail ".secrets untracked leak" || pass "no .secrets leak in status"

exit $FAIL
