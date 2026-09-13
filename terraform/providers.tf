# One provider, one region. CloudTrail multi-region (M2) is a trail attribute.

provider "aws" {
  region = var.region
  # Folds #31. Layer is per-resource; do not repeat these two keys.
  default_tags {
    tags = {
      Compliance = var.compliance_tag
      Project    = var.project_tag
    }
  }
}

# Identity for ARN construction and aws:SourceAccount (R-2).
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
