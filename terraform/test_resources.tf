# ---------------------------------------------------------------------------
# Dedicated, throwaway targets for the test scenarios (T1-T5). Nothing else in
# the account is ever touched by the tests.
#   - test user: no access keys, no console password, no permissions
#   - test policy: allows only sts:GetCallerIdentity (harmless)
#   - test bucket: created in s3.tf (key "test"), hardened like the others
# ---------------------------------------------------------------------------

resource "aws_iam_user" "test" {
  name = "${var.name_prefix}-test-user"
  path = "/${var.name_prefix}/"
}

data "aws_iam_policy_document" "test_policy" {
  statement {
    sid       = "HarmlessTestStatement"
    effect    = "Allow"
    actions   = ["sts:GetCallerIdentity"]
    resources = ["*"] # GetCallerIdentity does not support resource-level permissions
  }
}

resource "aws_iam_policy" "test" {
  name        = "${var.name_prefix}-test-policy"
  path        = "/${var.name_prefix}/"
  description = "Harmless managed policy used by test scenario T1 (attach/detach)."
  policy      = data.aws_iam_policy_document.test_policy.json
}
