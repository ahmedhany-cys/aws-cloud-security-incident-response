# My Tasks (manual steps for the project owner)

This guide lists every step that Claude cannot or must not do for you.
Work through them in order. Each step says why it is needed, exactly what to
click or paste, what success looks like, and when to stop and tell Claude.

Status legend: **BLOCKING** = Claude cannot continue until this is done.
**LATER** = needed at a later phase. **DONE** = already verified.

Environment check results (2026-10-23):

| Check | Result |
|---|---|
| `aws --version` | aws-cli 2.36.40 (OK) |
| AWS profile `sec-ir` | **missing** (only `default`, `siem_project`, `siem_project_attacker` exist) |
| `terraform version` | Terraform v1.17.0 (installed by Claude 2026-10-23, DONE) |
| `gh auth status` | gh 2.103.0 installed (DONE), but **not logged in** → step 5 |
| `python3 --version` | Python 3.14.7 (OK) |
| `pytest`, `boto3` | installed in project `.venv` (boto3 1.43.118, pytest 9.1.1, DONE) |
| `git --version` | git 2.39.5 (OK) |
| Homebrew | 6.0.22 (OK, used for installs below) |
| Browser tools | Built-in browser pane and Claude in Chrome are both available, so Claude can take console screenshots once you are signed in |

---

## 0. Provide the project spec (CLAUDE.md) — DONE (2026-10-23, copied from Downloads into the project)

**Why:** CLAUDE.md is the spec and rulebook for the whole build (phases, resources, Free Tier guardrails, test scenarios T1 to T6). This session was started with no folder, and no file named `CLAUDE.md` exists anywhere on this Mac. Nothing beyond this guide can be built without it.

**What to do (pick one):**
1. If the spec lives in a folder on this Mac, tell Claude the folder path (for example `~/Documents/aws-sec-ir`). Claude will move the session there.
2. Otherwise, paste the full contents of CLAUDE.md into the chat, and say which folder the project should live in (for example `~/Documents/aws-cloud-security-incident-response`).

**You should see:** Claude confirms it read the spec and lists the phases it found.

**Stop and tell Claude if:** you do not have a CLAUDE.md. Claude will then ask you to describe the project instead.

---

## 1. Install the missing tools — DONE (Claude installed them with your approval on 2026-10-23)

**Why:** Terraform builds the AWS resources, `gh` creates and pushes the GitHub repo, and `pytest` plus `boto3` run the automated tests. Claude will not install software on your Mac without your explicit yes.

**Option A: you run the commands.** Open Terminal and paste each line, one at a time:

```bash
brew tap hashicorp/tap && brew install hashicorp/tap/terraform
```

```bash
brew install gh
```

```bash
python3 -m pip install --user boto3 pytest
```

**Option B: tell Claude "yes, install the tools"** and it will run exactly the three commands above. For Python it will prefer a project-local virtual environment (`.venv` inside the project folder) so nothing touches your system Python.

**You should see:**
- `terraform version` prints `Terraform v1.x.x`
- `gh --version` prints `gh version 2.x.x`
- `python3 -c "import boto3, pytest; print('ok')"` prints `ok`

**Stop and tell Claude if:** any command ends with `Error:` or the version check prints `command not found`. Paste the full output.

---

## 2. Create the dedicated IAM user and access key — BLOCKING

**Why:** The build must never use your root account. A dedicated user with a single access key can be deleted at the end, which limits the damage if the key ever leaks.

**Exact console path:**
1. Sign in to https://console.aws.amazon.com with your **own IAM user or root** (root is allowed only for this setup step, never for the build).
2. Top search bar → type **IAM** → open **IAM**.
3. Left menu → **Users** → **Create user**.
4. User name: `aws-sec-ir-deployer`. Leave "Provide user access to the AWS Management Console" **unchecked**. → **Next**.
5. Permissions options: select **Attach policies directly**. Do not pick anything yet (the policy is attached in step 3). → **Next** → **Create user**.
6. Click the new user **aws-sec-ir-deployer** → tab **Security credentials** → section **Access keys** → **Create access key**.
7. Use case: **Command Line Interface (CLI)**. Tick the confirmation box → **Next** → Description tag: `aws-sec-ir build` → **Create access key**.
8. Keep this page open. You will see **Access key** and **Secret access key**. Do not paste either into the chat with Claude.

**Configure the CLI profile (in Terminal):**

```bash
aws configure --profile sec-ir
```

Answer the four prompts:
- AWS Access Key ID: paste the access key
- AWS Secret Access Key: paste the secret
- Default region name: `us-east-1`
- Default output format: `json`

Then verify:

```bash
aws sts get-caller-identity --profile sec-ir
```

**You should see:** a JSON block whose `Arn` ends in `:user/aws-sec-ir-deployer`.

**Stop and tell Claude if:** the `Arn` contains `:root`, or the command prints `InvalidClientTokenId` or `could not be found`.

---

## 3. Review and attach the deployer policy — BLOCKING

**Why:** The deployer user needs just enough permission to create the resources in CLAUDE.md and nothing more. Claude drafts the policy as `docs/deployer-policy.json`; you review and attach it, so Claude never grants itself permissions.

**Status:** `docs/deployer-policy.json` is drafted and ready for your review. It allows the deployer to create and delete only `aws-sec-ir-*` resources in S3, CloudTrail, IAM, Lambda, EventBridge, CloudWatch Logs and SNS, plus the read-only List/Describe/Lookup calls that AWS does not scope by resource.

**Exact console path (once the file exists):**
1. Open `docs/deployer-policy.json` in the project folder and read it. Every `Action` should be a service named in CLAUDE.md, and every `Resource` should be scoped to the `aws-sec-ir` prefix where the service allows it.
2. Console → **IAM** → **Policies** → **Create policy** → tab **JSON**.
3. Delete the sample text, paste the whole file, → **Next**.
4. Policy name: `aws-sec-ir-deployer-policy` → **Create policy**.
5. **IAM** → **Users** → **aws-sec-ir-deployer** → **Add permissions** → **Attach policies directly** → search `aws-sec-ir-deployer-policy` → tick it → **Next** → **Add permissions**.

**You should see:** the user's Permissions tab lists `aws-sec-ir-deployer-policy`.

**Stop and tell Claude if:** the console shows a red validation error when you paste the JSON. Paste the error text to Claude.

---

## 4. Set a billing budget — BLOCKING (protects you from surprise charges)

**Why:** Everything in this project is designed for the Free Tier, but a budget is the safety net. Email alerts for the *project itself* are off per your settings; the budget email is different and goes only to you.

**Exact console path:**
1. Console → top-right account name → **Billing and Cost Management**.
2. Left menu → **Budgets** → **Create budget**.
3. Choose **Use a template (simplified)** → **Zero spend budget** (alerts the moment anything is billed). If you prefer a small allowance, choose **Monthly cost budget** and enter `5` USD.
4. Budget name: `aws-sec-ir-budget`. Email recipients: your email address. → **Create budget**.

**You should see:** `aws-sec-ir-budget` listed with status **OK**.

**Stop and tell Claude if:** the Budgets page says the account is not yet eligible (brand-new accounts can take up to 24 hours). You can continue; just tell Claude the budget is pending.

---

## 5. Sign in to GitHub from the terminal — BLOCKING (needed at the end)

**Why:** Claude creates the public repo `aws-cloud-security-incident-response` and pushes with the `gh` CLI, which needs your GitHub login. The login flow uses a browser code, so you must do it yourself.

**Command (after step 1 installed gh):**

```bash
gh auth login
```

Answers: **GitHub.com** → **HTTPS** → **Yes** (authenticate Git with your GitHub credentials) → **Login with a web browser** → copy the one-time code → press Enter → paste the code in the browser → **Authorize**.

Verify:

```bash
gh auth status
```

**You should see:** `Logged in to github.com account <your-username>`.

**Stop and tell Claude if:** it prints `You are not logged into any GitHub hosts`.

---

## 6. Sign in to the AWS console for screenshots — LATER (Phase 6)

**Why:** Claude has a browser pane and can take the console screenshots, but it must never type your password or MFA code. You sign in; Claude only navigates and captures.

**What to do when Claude asks:**
1. Claude will open the browser pane at https://console.aws.amazon.com and tell you.
2. Sign in there as your normal IAM user (not root) and complete MFA yourself.
3. Say "signed in" in the chat.

**You should see:** the AWS console home page inside the browser pane.

**Stop and tell Claude if:** the sign-in page blocks the embedded browser. Claude will then switch to the screenshot checklist in section 7.

---

## 7. Screenshots to take yourself (fallback only) — LATER

Used only if the browser pane cannot reach the console. Save each as PNG under `docs/screenshots/` with the exact filename, and blur or crop the account ID (top-right) before saving.

The exact list depends on the resources in CLAUDE.md and will be filled in once the spec is available. Typical items:

| Filename | Console path |
|---|---|
| `01-cloudtrail-trail.png` | CloudTrail → Trails → the `aws-sec-ir-*` trail |
| `02-guardduty-findings.png` | GuardDuty → Findings, filtered to the test finding |
| `03-eventbridge-rule.png` | EventBridge → Rules → the `aws-sec-ir-*` rule |
| `04-lambda-responder.png` | Lambda → Functions → the responder function → Monitor tab |
| `05-s3-audit-bucket.png` | S3 → the audit bucket → Properties (versioning, encryption, Object Lock) |

---

## 8. Clean up when finished — LATER (do not do this yet)

**Why:** Removes every resource so nothing can bill you, then removes the key so it can never be used.

1. Ask Claude to run the teardown (it will show you the destroy plan first and wait for your yes). The command it will run, from the project folder:

```bash
terraform destroy -var-file=terraform.tfvars
```

2. Console → **IAM** → **Users** → **aws-sec-ir-deployer** → **Security credentials** → the access key → **Actions** → **Deactivate**, then **Delete**.
3. Optionally delete the user itself, and remove the local profile: edit `~/.aws/credentials` and delete the `[sec-ir]` block.

**You should see:** `terraform destroy` ends with `Destroy complete!`, and the user shows no access keys.

---

## 9. Tell Claude the bucket suffix — BLOCKING

**Why:** S3 bucket names are global, so each project bucket gets a unique suffix. Your settings say "initials + 4 digits".

**What to do:** reply with the suffix, lowercase letters and digits only, 4 to 16 characters. Example: `ahr2610`. Claude writes it into `terraform/terraform.tfvars` (gitignored).

## Extra manual steps discovered during the build

(Claude appends to this list as the build runs.)

- 2026-10-23: no Mermaid renderer (`mmdc`, Node) is installed, so `docs/architecture.png` is not generated; the Mermaid source in `docs/architecture.md` renders on GitHub. Optional: `brew install node && npm i -g @mermaid-js/mermaid-cli`, then tell Claude to export the PNG. **To do (optional).**
- 2026-10-23: `gitleaks` is not installed; the hygiene checks will use the three `git grep` checks from CLAUDE.md. Optional: `brew install gitleaks`. **To do (optional).**
