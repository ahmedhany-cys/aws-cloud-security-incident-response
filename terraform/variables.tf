variable "aws_profile" {
  description = "Named AWS CLI profile to deploy with (never root)."
  type        = string
  default     = "sec-ir"
}

variable "aws_region" {
  description = "Single deployment region. Must stay us-east-1 so IAM (global) events reach EventBridge."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = var.aws_region == "us-east-1"
    error_message = "This project must be deployed in us-east-1 (see CLAUDE.md, Region)."
  }
}

variable "name_prefix" {
  description = "Prefix for every resource name."
  type        = string
  default     = "aws-sec-ir"
}

variable "project_tag" {
  description = "Value of the Project tag applied to all resources."
  type        = string
  default     = "aws-sec-ir"
}

variable "environment" {
  description = "Value of the Environment tag."
  type        = string
  default     = "lab"
}

variable "bucket_suffix" {
  description = "Short unique suffix for bucket names (e.g. your initials + 4 digits). Lowercase letters and digits only."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]{4,16}$", var.bucket_suffix))
    error_message = "bucket_suffix must be 4-16 lowercase letters or digits."
  }
}

variable "enable_email_alerts" {
  description = "Create an SNS topic + email subscription and have the Lambda publish to it. Off by default."
  type        = bool
  default     = false
}

variable "alert_email" {
  description = "Email address for SNS alerts. Only used when enable_email_alerts = true."
  type        = string
  default     = ""
}

variable "lambda_log_retention_days" {
  description = "CloudWatch log retention for the Lambda log group."
  type        = number
  default     = 7
}

variable "s3_object_expiration_days" {
  description = "Days after which current objects in project buckets expire."
  type        = number
  default     = 30
}

variable "s3_noncurrent_expiration_days" {
  description = "Days after which noncurrent object versions expire."
  type        = number
  default     = 7
}
