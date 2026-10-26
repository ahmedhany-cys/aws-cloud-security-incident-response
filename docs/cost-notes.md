# Cost notes

Goal: run this project at zero (or near-zero) cost. Every choice below was made
against the AWS Free Tier as documented on 2026-10-23. Check your own account's
plan (section 1) because the two Free Tier models differ.

## 1. Which Free Tier model does this account use?

AWS has two models:

| Model | Who | What you get |
|---|---|---|
| **Credit-based plan** (accounts created on or after 15 July 2025) | New accounts | Up to USD 200 in credits (100 at sign-up, up to 100 more for completing activities), valid 6 months or until used. After that the account must be upgraded to a paid plan. "Always free" services keep their always-free limits. |
| **Legacy 12-month Free Tier** (accounts created before 15 July 2025) | Older accounts | 12 months of monthly free allowances per service plus the always-free tier. |

How to check: Console → Billing and Cost Management → **Free Tier** page, or:

```bash
aws freetier get-account-plan-state --profile sec-ir
```

> **Result for this account (checked 2026-10-26 with `aws freetier get-account-plan-state`):**
> - Plan type: **FREE** (the credit-based plan), status **ACTIVE**.
> - Remaining credits: the API reported **USD 100.78**; the console's Free Tier page showed **USD 120.78** the same morning (screenshot 11). The two views can differ while credit activities are still being applied; trust the console's Credits page.
> - Plan expiration date: **2026-11-30**.
>
> What this means: usage of this project is either inside the always-free limits or drawn from credits, so no card charge is expected. **Before 2026-11-30 you must either upgrade the account to a paid plan or tear the project down.** On the free plan, AWS closes the account after the expiry date unless it is upgraded, and resources are then deleted after a grace period. Teardown steps are in [teardown.md](teardown.md).
>
> Budgets present: `aws-sec-ir-budget` (USD 1, created for this project) plus two pre-existing budgets in the account.

## 2. Per-service free-tier status

| Service | Used how | Free tier | Expected monthly cost |
|---|---|---|---|
| CloudTrail | one trail, management events, read+write, single region | The first copy of management events delivered to S3 is free (always free). Data events, Insights and additional trails cost money and are **not** used. | $0 |
| S3 | 3 small buckets; CloudTrail log files + a handful of JSON reports | Always free: 5 GB standard storage (legacy tier: 12 months; credit plan: covered by credits), 20k GET, 2k PUT per month. Lifecycle rule deletes everything after 30 days (noncurrent versions after 7). | $0 (far below 5 GB) |
| EventBridge | 3 rules on the default bus matching AWS-service events | Events published by AWS services are free; rules are free. Custom/partner events would cost, none are used. | $0 |
| Lambda | 128 MB, 30 s timeout, invoked only on matched events | Always free: 1M requests and 400k GB-seconds per month. | $0 |
| CloudWatch Logs | Lambda log group, 7-day retention | 5 GB ingestion + storage free per month. CloudTrail → CloudWatch Logs delivery is **disabled** (that is where surprise costs usually come from). | $0 |
| IAM | roles, policies, test user | Always free. | $0 |
| EventBridge Scheduler | 1 schedule, `rate(5 minutes)`, invokes the trail health check (about 8,640 runs/month) | 14 million invocations free per month. | $0 |
| Lambda (health check) | 128 MB, runs about 8,640 times/month, well under a second each | Inside the same always-free 1M requests and 400k GB-seconds. | $0 |
| SNS | optional email topic (off by default) | 1,000 email notifications free per month. | $0 |
| Out of scope | GuardDuty, Security Hub, Config, Macie, Inspector | Not free long-term; deliberately excluded. | n/a |

## 3. What could cost money (and how it is prevented)

- **A second trail or an organization trail** → additional copies of management events are billed. Prevented: Terraform creates exactly one trail. Check CloudTrail → Trails shows only `aws-sec-ir-trail` (plus any pre-existing trails that are not part of this project).
- **Data events / Insights** → billed per 100k events. Prevented: `event_selector` has no `data_resource` and no `insight_selector`.
- **CloudTrail → CloudWatch Logs** → ingestion billed per GB. Prevented: no `cloud_watch_logs_group_arn` on the trail.
- **S3 growth** → lifecycle expiry (30 d / 7 d) keeps storage tiny.
- **Lambda runaway loop** → the Lambda's own `PutObject` is an S3 *data* event, which CloudTrail does not record (data events are off), so a report write can never trigger another detection.
- **KMS** → SSE-S3 (AES256) is used instead of SSE-KMS; no key charges.

## 4. What to check in Billing

1. Billing and Cost Management → **Free Tier**: usage of S3, Lambda, CloudWatch should all show tiny percentages.
2. Billing and Cost Management → **Budgets**: the `aws-sec-ir-budget` zero-spend (or 5 USD) budget shows OK.
3. Billing and Cost Management → **Bills** → filter by service: CloudTrail, S3, Lambda, EventBridge, CloudWatch should each be $0.00.
4. Cost Explorer (optional) → group by tag `Project` once tag-based allocation is activated (takes 24 h).

## 5. Teardown reminder

Nothing here runs up a bill while idle, but the trail keeps writing log files until it is destroyed. Follow [teardown.md](teardown.md) when the project is finished.
