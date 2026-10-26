# Teardown

Run this only when you are finished with the project. Order matters: versioned
buckets must be emptied (all versions and delete markers) before Terraform can
delete them.

## 1. Empty the versioned buckets

The audit and incident buckets have `force_destroy = false` (so a mistaken
`destroy` cannot wipe evidence). Empty them explicitly:

```bash
scripts/empty_bucket.sh "$(terraform -chdir=terraform output -raw audit_bucket)"
```

```bash
scripts/empty_bucket.sh "$(terraform -chdir=terraform output -raw incident_bucket)"
```

The test bucket has `force_destroy = true`; Terraform empties it itself.

## 2. Make sure nothing is attached to the test user

T1 and T2 detach/delete what they add, but double-check:

```bash
aws iam list-attached-user-policies --user-name aws-sec-ir-test-user --profile sec-ir
```

```bash
aws iam list-user-policies --user-name aws-sec-ir-test-user --profile sec-ir
```

Both should return empty lists.

## 3. Destroy

```bash
terraform -chdir=terraform plan -destroy -out=tfplan-destroy
```

Review the plan (every resource should be tagged `Project = aws-sec-ir`), then:

```bash
terraform -chdir=terraform apply tfplan-destroy
```

## 4. Confirm nothing is left

```bash
aws resourcegroupstaggingapi get-resources --tag-filters Key=Project,Values=aws-sec-ir --region us-east-1 --profile sec-ir --query 'ResourceTagMappingList[].ResourceARN'
```

Expected: `[]`. IAM resources and the schedule itself are not returned by the tagging API, so also run:

```bash
aws scheduler list-schedule-groups --region us-east-1 --profile sec-ir --query "ScheduleGroups[?Name=='aws-sec-ir'].Name"
```

Expected: `[]`.

```bash
aws iam list-roles --path-prefix / --query "Roles[?starts_with(RoleName,'aws-sec-ir')].RoleName" --profile sec-ir
```

Expected: `[]`.

## 5. Remove the deployer access key

Console → IAM → Users → `aws-sec-ir-deployer` → Security credentials → access key → Deactivate → Delete. Then remove the `[sec-ir]` block from `~/.aws/credentials` and `~/.aws/config`.
