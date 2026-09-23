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

# Layer 2

variable "minimum_password_length" {
  type        = number
  default     = 14
  description = "IAM password minimum. 14 covers FedRAMP High (12) and CJIS/NIST 800-63B AAL2 guidance."
  validation {
    condition     = var.minimum_password_length >= 14 && var.minimum_password_length <= 128
    error_message = "Minimum password length must be between 14 and 128."
  }
}

variable "max_password_age_days" {
  type        = number
  default     = 90
  description = "Days before IAM passwords expire. 90 is the historical FedRAMP/CJIS baseline."
  validation {
    condition     = var.max_password_age_days >= 1 && var.max_password_age_days <= 1095
    error_message = "Max password age must be between 1 and 1095 days."
  }
}

variable "password_reuse_prevention" {
  type        = number
  default     = 24
  description = "Prior passwords blocked from reuse. 24 is the IAM max and the FedRAMP High value."
  validation {
    condition     = var.password_reuse_prevention >= 1 && var.password_reuse_prevention <= 24
    error_message = "Password reuse prevention must be between 1 and 24."
  }
}

variable "admin_role_external_id" {
  type        = string
  sensitive   = true
  description = "sts:ExternalId required to assume AdminRole. Set a long random string in terraform.tfvars."
  validation {
    condition     = length(var.admin_role_external_id) >= 16
    error_message = "ExternalId must be at least 16 characters."
  }
}

variable "admin_role_suffix" {
  type        = string
  default     = "admin"
  description = "AdminRole name and the matching Deny ARN inside AdminPermissionsBoundary."
}

variable "auditor_role_suffix" {
  type        = string
  default     = "auditor"
  description = "AuditorRole name. No permissions boundary; the Deny can reference its ARN directly."
}

variable "bucket_policy_admin_role_suffix" {
  type        = string
  default     = "bucket-policy-admin"
  description = "BucketPolicyAdminRole name. AdminPermissionsBoundary Deny already uses this string."
}

# Layer 4. Password checks reuse the Layer 2 variables; no new password inputs.

variable "config_snapshot_delivery_frequency" {
  type        = string
  default     = "Twelve_Hours"
  description = "How often Config writes a full snapshot. Configuration changes are recorded continuously either way."
  validation {
    condition = contains([
      "One_Hour",
      "Three_Hours",
      "Six_Hours",
      "Twelve_Hours",
      "TwentyFour_Hours",
    ], var.config_snapshot_delivery_frequency)
    error_message = "Must be One_Hour, Three_Hours, Six_Hours, Twelve_Hours, or TwentyFour_Hours."
  }
}

variable "config_bucket_object_lock_days" {
  type        = number
  default     = 365
  description = "Object Lock COMPLIANCE retention on the Config bucket. 365 is the FedRAMP High AU-11 floor."
  validation {
    condition     = var.config_bucket_object_lock_days >= 1
    error_message = "Object Lock retention must be at least 1 day."
  }
}
