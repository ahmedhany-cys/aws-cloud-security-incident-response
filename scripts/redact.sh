#!/usr/bin/env bash
# Redact 12-digit AWS account IDs and email addresses.
# Usage: scripts/redact.sh <file>...        (rewrites each file in place)
#        some-command | scripts/redact.sh   (filter stdin -> stdout)
set -euo pipefail

ACCOUNT_RE='[0-9]{12}'
EMAIL_RE='[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'

redact() {
  sed -E -e "s/${ACCOUNT_RE}/123456789012/g" -e "s/${EMAIL_RE}/redacted@example.com/g"
}

if [ "$#" -eq 0 ]; then
  redact
else
  for f in "$@"; do
    tmp="$(mktemp)"
    redact < "$f" > "$tmp"
    mv "$tmp" "$f"
  done
fi
