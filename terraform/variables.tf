# Layer 3 variables. Later milestones append theirs under a layer comment.

variable "region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region for this baseline. Single region except CloudTrail multi-region in M2."
}

variable "project_tag" {
  type        = string
  default     = "aws-compliance-as-code"
  description = "Project tag applied via provider default_tags."
}

variable "compliance_tag" {
  type        = string
  default     = "NIST-800-53-Rev5"
  description = "Compliance tag applied via provider default_tags. Matches Layer 1's CloudFormation value."
}

variable "key_administrator_role_arn" {
  type        = string
  description = "IAM role ARN that ADMINISTERS the CMK. Use the Layer 2 admin role once M3 ships it. No default."

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+", var.key_administrator_role_arn))
    error_message = "Must be a full IAM role ARN, e.g. arn:aws:iam::<account>:role/<name> (aws-us-gov and aws-cn partitions also accepted)."
  }
}

variable "key_alias_name" {
  type        = string
  default     = "alias/compliance-baseline-cmk"
  description = "Friendly alias for the CMK. Callers use this stable name while key material rotates."

  validation {
    condition     = can(regex("^alias/[a-zA-Z0-9/_-]+$", var.key_alias_name))
    error_message = "Must start with \"alias/\" then alphanumerics, dashes, underscores, or slashes."
  }
}

variable "pending_deletion_window_days" {
  type        = number
  default     = 30
  description = "Days KMS waits after deletion is scheduled. 30 (API maximum) is the conservative default."

  validation {
    condition     = var.pending_deletion_window_days >= 7 && var.pending_deletion_window_days <= 30
    error_message = "Pending deletion window must be between 7 and 30 days."
  }
}
