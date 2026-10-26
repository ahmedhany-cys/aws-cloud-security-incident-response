# Evidence

Redacted CLI and JSON outputs produced by `scripts/run_test_scenarios.sh` and
`scripts/collect_evidence.sh`. `scripts/redact.sh` replaces account IDs with
`123456789012`, emails with `redacted@example.com`, IPv4 addresses with
`203.0.113.10`, access key IDs with `AKIA_REDACTED` and IAM unique IDs with
`AIDA_REDACTED`. Unredacted originals stay in `raw/`, which is gitignored.

Layout:

- Top level: the final results. T1, T2, T4, T5, T6 from run 2 and T3 from run 3, plus stack evidence (`00-` to `12-`). `results.tsv` lists every attempt.
- `run1/`: the first run (T1 to T5). Includes the failed T5 and its diagnosis. Its incident reports still contain the since-removed `eventbridge_rule: null` field.
- `run2-T3/`: the failed second T3 attempt and its diagnosis.
- `T7-*` (top level): the passing T7 run (run 5) of the scheduled trail health check. `00c-terraform-apply-health-check.txt` is its deploy.
- `run4-T7-scriptbug/`: the first T7 run, where the health check worked but the script's run counter failed; `NOTE.txt` explains.

Naming: `Tn-command.txt` (the trigger), `Tn-restore.txt` / `Tn-verify-restored.txt`
(state restored), `Tn-incident.json` (the report the Lambda wrote),
`Tn-lambda-log.txt` (CloudWatch excerpt), `Tn-cloudtrail-lookup.json`
(the CloudTrail record), `results.tsv` (pass/fail summary).
