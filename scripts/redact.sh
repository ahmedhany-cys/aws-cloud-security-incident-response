#!/usr/bin/env bash
# Redact 12-digit AWS account IDs, email addresses, IPv4 addresses, access key
# IDs (AKIA/ASIA) and IAM unique principal IDs (AIDA/AROA)
# (source IPs reveal the operator's network; replaced with 203.0.113.10,
# an RFC 5737 documentation address).
# Usage: scripts/redact.sh <file>...        (rewrites each file in place)
#        some-command | scripts/redact.sh   (filter stdin -> stdout)
set -euo pipefail

ACCOUNT_RE='[0-9]{12}'
EMAIL_RE='[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
KEYID_RE='(AKIA|ASIA)[0-9A-Z]{12,}'
PRINCIPAL_RE='(AIDA|AROA)[0-9A-Z]{12,}'
IPV4_RE='(^|[^0-9.])([0-9]{1,3}\.){3}[0-9]{1,3}([^0-9.]|$)'

redact() {
  sed -E -e "s/${ACCOUNT_RE}/123456789012/g" -e "s/${EMAIL_RE}/redacted@example.com/g" \
        -e "s/${IPV4_RE}/\1203.0.113.10\3/g" \
        -e "s/${KEYID_RE}/AKIA_REDACTED/g" -e "s/${PRINCIPAL_RE}/AIDA_REDACTED/g"
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
