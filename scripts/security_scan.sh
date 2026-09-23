#!/usr/bin/env sh
# Security checks against a running Asber deployment, mapped to OWASP Top 10:2025.
#
# A unit test cannot prove that the edge is configured correctly: whether the
# API really is unreachable without a session, whether TLS and the security
# headers are actually applied. This checks the assembled system.
#
#   ./scripts/security_scan.sh https://asber.example.com
#   ./scripts/security_scan.sh https://localhost -k     # local test, private CA
#
# Exit code 0 means every check passed. Anything else means do not deploy.
set -eu

BASE="${1:-https://localhost}"
CURL="curl -s -o /dev/null -m 20"
[ "${2:-}" = "-k" ] && CURL="$CURL -k"
BODY="curl -s -m 20"
[ "${2:-}" = "-k" ] && BODY="$BODY -k"

pass=0
fail=0

check() { # check <name> <expected> <actual>
  if [ "$2" = "$3" ]; then
    printf '  PASS  %-52s %s\n' "$1" "$3"
    pass=$((pass + 1))
  else
    printf '  FAIL  %-52s got %s, expected %s\n' "$1" "$3" "$2"
    fail=$((fail + 1))
  fi
}

code() { $CURL -w '%{http_code}' "$@"; }

echo "Scanning $BASE"
echo
echo "A01 Broken Access Control — nothing is reachable without a session"
for path in /api/health /api/vulnerabilities /api/settings /api/metrics /api/sources; do
  check "GET $path" 401 "$(code "$BASE$path")"
done
check "POST /api/sources/cisa_kev/run" 401 "$(code -X POST "$BASE/api/sources/cisa_kev/run")"
check "GET / redirects to sign-in" 307 "$(code "$BASE/")"
check "GET /login is public" 200 "$(code "$BASE/login")"

echo
echo "A01 — bypass attempts"
# A static-asset exclusion in the matcher once let these through to the backend.
for ext in png svg ico webmanifest; do
  check "GET /api/health.$ext" 401 "$(code "$BASE/api/health.$ext")"
done
# CVE-2025-29927: a crafted header skipped Next.js middleware entirely.
check "x-middleware-subrequest header" 401 \
  "$(code -H 'x-middleware-subrequest: middleware' "$BASE/api/health")"
check "forged session cookie" 401 \
  "$(code -H 'Cookie: __Secure-authjs.session-token=a.b.c' "$BASE/api/health")"
check "traversal /_next/../api/health" 401 "$(code --path-as-is "$BASE/_next/../api/health")"

echo
echo "A02 Security Misconfiguration — headers"
headers=$($BODY -D - -o /dev/null "$BASE/login")
for h in "strict-transport-security" "x-frame-options" "x-content-type-options" \
         "referrer-policy" "content-security-policy"; do
  if printf '%s' "$headers" | grep -qi "^$h:"; then
    printf '  PASS  %-52s present\n' "$h"; pass=$((pass + 1))
  else
    printf '  FAIL  %-52s MISSING\n' "$h"; fail=$((fail + 1))
  fi
done
for h in "server" "x-powered-by"; do
  if printf '%s' "$headers" | grep -qi "^$h:"; then
    printf '  FAIL  %-52s leaked\n' "$h"; fail=$((fail + 1))
  else
    printf '  PASS  %-52s not disclosed\n' "$h"; pass=$((pass + 1))
  fi
done

echo
echo "A04 Cryptographic Failures — transport and cookies"
plain=$(printf '%s' "$BASE" | sed 's|^https://|http://|')
check "HTTP redirects to HTTPS" 308 "$(code "$plain/login")"
cookies=$($BODY -D - -o /dev/null "$BASE/api/auth/csrf" | grep -i '^set-cookie' || true)
for flag in HttpOnly Secure SameSite; do
  if printf '%s' "$cookies" | grep -qi "$flag"; then
    printf '  PASS  %-52s set\n' "cookie $flag"; pass=$((pass + 1))
  else
    printf '  FAIL  %-52s MISSING\n' "cookie $flag"; fail=$((fail + 1))
  fi
done

echo
echo "A07 Authentication Failures — the sign-in flow is actually reachable"
# A blanket /api proxy once swallowed these, so sign-in could never complete.
for path in /api/auth/providers /api/auth/csrf /api/auth/session; do
  check "GET $path" 200 "$(code "$BASE$path")"
done

echo
echo "A09 Logging — the health of collection is observable"
check "GET /sources redirects when signed out" 307 "$(code "$BASE/sources")"

echo
printf '%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
