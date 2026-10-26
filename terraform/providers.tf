provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile

  # Every resource this project creates carries these tags. Scripts and the
  # teardown check rely on Project = aws-sec-ir to find project resources.
  default_tags {
    tags = {
      Project     = var.project_tag
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
