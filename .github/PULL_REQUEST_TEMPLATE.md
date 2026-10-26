## What changed

<!-- One or two sentences. Link the issue if there is one. -->

## Why

<!-- The problem this solves or the behaviour it adds. -->

## Checklist

- [ ] `python -m pytest` passes (no AWS access needed)
- [ ] `ruff check lambda tests scripts` is clean
- [ ] `terraform -chdir=terraform fmt -check` and `terraform -chdir=terraform validate` pass
- [ ] `shellcheck scripts/*.sh` is clean (if scripts changed)
- [ ] `python3 scripts/check_docs_links.py` passes (if docs changed)
- [ ] No secrets, state files, real account IDs, IPs or key IDs in the diff
- [ ] Docs updated if behaviour, detection rules or the incident schema changed
- [ ] New or changed detection rules have a sample event in `tests/events/` and a unit test

## How it was verified

<!-- Unit tests only, or a live scenario? If live, which test ID and what was observed. -->
