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

# Layer 1

variable "trail_name" {
  type        = string
  default     = "org-cloudtrail"
  description = "Name of the multi-region CloudTrail trail."
}

variable "cloudtrail_retention_days" {
  type        = number
  default     = 365
  description = "CloudWatch retention for the CloudTrail group. Object Lock is the long-term store."
  validation {
    condition     = contains([30, 60, 90, 180, 365, 400, 545, 731, 1827, 3653], var.cloudtrail_retention_days)
    error_message = "Must be a CloudWatch Logs retention AWS accepts: 30, 60, 90, 180, 365, 400, 545, 731, 1827, or 3653."
  }
}

variable "flow_logs_retention_days" {
  type        = number
  default     = 90
  description = "CloudWatch retention for the VPC Flow Logs group. Default 90; volume is 10-100x CloudTrail."
  validation {
    condition     = contains([30, 60, 90, 180, 365, 400, 545, 731, 1827, 3653], var.flow_logs_retention_days)
    error_message = "Must be a CloudWatch Logs retention AWS accepts: 30, 60, 90, 180, 365, 400, 545, 731, 1827, or 3653."
  }
}

variable "default_vpc_id" {
  type        = string
  description = "VPC to attach Flow Logs to. Required; no default-VPC intrinsic."
  validation {
    condition     = can(regex("^vpc-", var.default_vpc_id))
    error_message = "Must be a VPC id (starts with vpc-)."
  }
}
