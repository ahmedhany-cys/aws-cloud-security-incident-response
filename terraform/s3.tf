# ---------------------------------------------------------------------------
# Shared bucket hardening. Each bucket gets: versioning, SSE-S3, lifecycle
# expiry (30 d current / 7 d noncurrent), Block Public Access, ACLs disabled,
# and a deny-non-TLS policy. Only the audit bucket additionally allows
# CloudTrail to write.
# ---------------------------------------------------------------------------

locals {
  buckets = {
    audit = {
      name          = local.audit_bucket_name
      force_destroy = false # emptied by docs/teardown.md before destroy
    }
    incidents = {
      name          = local.incident_bucket_name
      force_destroy = false
    }
    test = {
      name          = local.test_bucket_name
      force_destroy = true # throwaway; safe to wipe on destroy
    }
  }
}

resource "aws_s3_bucket" "this" {
  for_each      = local.buckets
  bucket        = each.value.name
  force_destroy = each.value.force_destroy
}

resource "aws_s3_bucket_ownership_controls" "this" {
  for_each = aws_s3_bucket.this
  bucket   = each.value.id
  rule {
    object_ownership = "BucketOwnerEnforced" # ACLs disabled
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  for_each                = aws_s3_bucket.this
  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "this" {
  for_each = aws_s3_bucket.this
  bucket   = each.value.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  for_each = aws_s3_bucket.this
  bucket   = each.value.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # SSE-S3: no KMS cost
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  for_each   = aws_s3_bucket.this
  bucket     = each.value.id
  depends_on = [aws_s3_bucket_versioning.this]

  rule {
    id     = "expire-objects"
    status = "Enabled"
    filter {}

    expiration {
      days = var.s3_object_expiration_days
    }
    noncurrent_version_expiration {
      noncurrent_days = var.s3_noncurrent_expiration_days
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# --- Policies ---------------------------------------------------------------

data "aws_iam_policy_document" "deny_insecure_transport" {
  for_each = aws_s3_bucket.this

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [each.value.arn, "${each.value.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

# CloudTrail delivery permissions, scoped to this one trail via aws:SourceArn.
data "aws_iam_policy_document" "audit_bucket" {
  source_policy_documents = [data.aws_iam_policy_document.deny_insecure_transport["audit"].json]

  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.this["audit"].arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.this["audit"].arn}/AWSLogs/${local.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "audit" {
  bucket     = aws_s3_bucket.this["audit"].id
  policy     = data.aws_iam_policy_document.audit_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.this]
}

resource "aws_s3_bucket_policy" "incidents" {
  bucket     = aws_s3_bucket.this["incidents"].id
  policy     = data.aws_iam_policy_document.deny_insecure_transport["incidents"].json
  depends_on = [aws_s3_bucket_public_access_block.this]
}

# The test bucket policy is deliberately managed here too, so T4 has a real
# policy to overwrite and the test script can restore it afterwards.
resource "aws_s3_bucket_policy" "test" {
  bucket     = aws_s3_bucket.this["test"].id
  policy     = data.aws_iam_policy_document.deny_insecure_transport["test"].json
  depends_on = [aws_s3_bucket_public_access_block.this]
}
