#!/usr/bin/env bash
# Empties a VERSIONED bucket: deletes every object version and delete marker.
# Only project buckets (aws-sec-ir-*) are accepted. Used by docs/teardown.md.
set -euo pipefail
bucket="${1:?usage: empty_bucket.sh <bucket-name>}"
[[ "$bucket" == aws-sec-ir-* ]] || { echo "refusing: $bucket is not a project bucket" >&2; exit 1; }
export AWS_PROFILE="${AWS_PROFILE:-sec-ir}" AWS_PAGER=""

delete_batch() { # $1 = JSON {"Objects":[...]} 
  local payload="$1"
  [ "$(printf '%s' "$payload" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["Objects"]))')" -gt 0 ] || return 0
  aws s3api delete-objects --bucket "$bucket" --delete "$payload" --output text > /dev/null
}

while :; do
  listing="$(aws s3api list-object-versions --bucket "$bucket" --max-items 1000 --output json)"
  versions="$(printf '%s' "$listing" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(json.dumps({"Objects":[{"Key":v["Key"],"VersionId":v["VersionId"]} for v in d.get("Versions",[])],"Quiet":True}))')"
  markers="$(printf '%s' "$listing" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(json.dumps({"Objects":[{"Key":v["Key"],"VersionId":v["VersionId"]} for v in d.get("DeleteMarkers",[])],"Quiet":True}))')"
  n=$(( $(printf '%s' "$versions" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["Objects"]))') + $(printf '%s' "$markers" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["Objects"]))') ))
  [ "$n" -eq 0 ] && break
  delete_batch "$versions"; delete_batch "$markers"
  echo "deleted $n versions/markers from $bucket"
done
echo "$bucket is empty"
