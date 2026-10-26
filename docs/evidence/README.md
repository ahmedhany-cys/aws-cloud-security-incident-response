# Evidence

Redacted CLI and JSON outputs produced by `scripts/run_test_scenarios.sh` and
`scripts/collect_evidence.sh`. Account IDs are replaced with `123456789012` and
email addresses with `redacted@example.com` by `scripts/redact.sh`. Unredacted
originals stay in `raw/` which is gitignored.

Naming: `Tn-command.txt` (the trigger), `Tn-restore.txt` / `Tn-verify-restored.txt`
(state restored), `Tn-incident.json` (the report the Lambda wrote),
`Tn-lambda-log.txt` (CloudWatch excerpt), `Tn-cloudtrail-lookup.json`
(the CloudTrail record), `results.tsv` (pass/fail summary).
