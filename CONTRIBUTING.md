# Contributing

Thanks for your interest. This is a small, single-maintainer lab project, so the
process is light, but the checks are real.

## Development setup

```bash
git clone https://github.com/ahmedhany-cys/aws-cloud-security-incident-response.git
cd aws-cloud-security-incident-response
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt ruff
```

Everything below runs without AWS credentials:

```bash
.venv/bin/python -m pytest                       # unit tests
.venv/bin/ruff check lambda tests scripts        # lint
terraform -chdir=terraform fmt -check -recursive # formatting
terraform -chdir=terraform init -backend=false   # providers only, no state
terraform -chdir=terraform validate
shellcheck -x scripts/*.sh                       # brew/apt install shellcheck
.venv/bin/python scripts/check_docs_links.py     # relative links in Markdown
```

CI runs the same checks on every pull request and every push to `main`
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

## Adding a detection rule

A rule touches four places. Keep them in sync:

1. **`terraform/main.tf`**: add the CloudTrail *event names* (not the API
   operation names) to the right entry in `local.detection_rules`, or add a new
   category.
2. **`lambda/incident_processor.py`**: add the same names to `LOOKUP` with a
   category, severity and recommended actions.
3. **`tests/events/`**: add a sample EventBridge event (copy a real, redacted
   one from `aws cloudtrail lookup-events`) and a test in
   `tests/test_incident_processor.py`.
4. **Docs**: the detection table in `README.md` and the reasoning in
   `docs/design-decisions.md`.

Verify each event name against a real logged event before opening the PR. Test
T5 in [`docs/test-cases.md`](docs/test-cases.md) shows what happens otherwise.

## Pull requests

- One change per PR, with a conventional commit message
  (`feat(detection): ...`, `fix(iam): ...`, `docs: ...`).
- Fill in the PR template, including how the change was verified.
- Never include state files, `.tfvars`, account IDs, IPs, access key IDs or
  principal IDs. Run `scripts/redact.sh` on any evidence you add.
- A change that could add cost outside the guardrails in
  [`docs/cost-notes.md`](docs/cost-notes.md) needs a clear justification and an
  opt-in variable that defaults to off.

## Running the live scenarios

`scripts/run_test_scenarios.sh` needs a deployed stack and the `sec-ir` CLI
profile. Read [`docs/test-cases.md`](docs/test-cases.md) and
[`docs/teardown.md`](docs/teardown.md) first. The scenarios only touch the
dedicated test resources, except T3 and T7, which stop the project trail and
restart it immediately.
