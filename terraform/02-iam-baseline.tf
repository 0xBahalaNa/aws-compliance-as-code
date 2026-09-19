# Layer 2 IAM core (AC-2/3/6, IA-5, CM-5): password policy, boundary, auditor/admin.

resource "aws_iam_account_password_policy" "compliance" {
  minimum_password_length        = var.minimum_password_length
  max_password_age               = var.max_password_age_days
  password_reuse_prevention      = var.password_reuse_prevention
  require_symbols                = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  allow_users_to_change_password = true
  hard_expiry                    = false
}

# Cap, not a grant. AdminRole ARN is string-built (role <-> boundary cycle). Name + Deny ARN share local.admin_boundary_name (#23).
data "aws_iam_policy_document" "admin_boundary" {
  #checkov:skip=CKV_AWS_1: AllowMostAdminActions is the boundary ceiling; Deny statements subtract.
  #checkov:skip=CKV_AWS_49: Resource "*" is required for an account-wide permissions boundary.
  #checkov:skip=CKV_AWS_107: DenyAccessKeysAndLoginProfiles Denies CreateAccessKey account-wide.
  #checkov:skip=CKV_AWS_108: Deny statements cover credential and log tampering; the Allow is the cap.
  #checkov:skip=CKV_AWS_109: Permissions-boundary documents attach to a principal, so Resource "*" is the IAM model.
  #checkov:skip=CKV_AWS_110: Allow * includes iam:* as the ceiling; the Deny Sids close the escalation paths #36 named.
  #checkov:skip=CKV_AWS_111: Deny statements constrain write verbs; the Allow is the cap.
  #checkov:skip=CKV_AWS_356: AdminRole is break-glass; ceiling is Allow * minus the Deny list.
  #checkov:skip=CKV2_AWS_40: Full IAM in the ceiling is the point of a permissions boundary; Deny Sids constrain it.
  statement {
    sid       = "AllowMostAdminActions"
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
  statement {
    sid    = "DenyAuditAndLoggingTampering"
    effect = "Deny"
    actions = [
      "cloudtrail:DeleteTrail", "cloudtrail:StopLogging", "cloudtrail:PutEventSelectors",
      "cloudtrail:UpdateTrail", "logs:DeleteLogGroup", "logs:DeleteRetentionPolicy",
      "s3:DeleteBucket", "s3:PutBucketPolicy",
    ]
    resources = ["*"]
  }
  statement {
    sid       = "DenyKmsKeyDestruction"
    effect    = "Deny"
    actions   = ["kms:ScheduleKeyDeletion", "kms:DisableKey", "kms:DeleteAlias"]
    resources = ["*"]
  }
  statement {
    sid    = "DenyIamBaselineTampering"
    effect = "Deny"
    actions = [
      "iam:DeleteAccountPasswordPolicy", "iam:UpdateAccountPasswordPolicy",
      "iam:DeleteRolePermissionsBoundary", "iam:PutUserPermissionsBoundary", "iam:DeleteUserPermissionsBoundary",
    ]
    resources = ["*"]
  }
  statement {
    sid    = "DenyComplianceRoleTampering"
    effect = "Deny"
    actions = [
      "iam:DeleteRole", "iam:DeleteRolePolicy", "iam:DetachRolePolicy",
      "iam:UpdateAssumeRolePolicy", "iam:PutRolePolicy",
    ]
    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.admin_role_suffix}",
      aws_iam_role.auditor.arn,
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.bucket_policy_admin_role_suffix}",
    ]
  }
  statement {
    sid       = "DenySiblingRoleEscalation"
    effect    = "Deny"
    actions   = ["iam:CreatePolicy", "iam:AttachRolePolicy", "iam:PutRolePermissionsBoundary"]
    resources = ["*"]
  }
  statement {
    sid       = "RequireBoundaryOnNewPrincipals"
    effect    = "Deny"
    actions   = ["iam:CreateUser", "iam:CreateRole"]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "iam:PermissionsBoundary"
      values   = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/${local.admin_boundary_name}"]
    }
  }
  statement {
    sid    = "DenyMutationWithoutBoundary"
    effect = "Deny"
    actions = [
      "iam:PutRolePolicy", "iam:PutUserPolicy", "iam:AttachUserPolicy", "iam:UpdateAssumeRolePolicy",
    ]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "iam:PermissionsBoundary"
      values   = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/${local.admin_boundary_name}"]
    }
  }
  statement {
    sid       = "DenyAccessKeysAndLoginProfiles"
    effect    = "Deny"
    actions   = ["iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile"]
    resources = ["*"]
  }
  statement {
    sid       = "DenyBoundarySelfMutation"
    effect    = "Deny"
    actions   = ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:DeletePolicy", "iam:DeletePolicyVersion"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "admin_boundary" {
  name        = local.admin_boundary_name
  description = "Maximum permissions cap for AdminRole."
  policy      = data.aws_iam_policy_document.admin_boundary.json
  tags        = { Layer = "2-IAM" }
}

data "aws_iam_policy_document" "auditor_trust" {
  statement {
    sid     = "TrustAccountPrincipalsWithMFA"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
    condition {
      test     = "NumericLessThan"
      variable = "aws:MultiFactorAuthAge"
      values   = ["3600"]
    }
  }
}

resource "aws_iam_role" "auditor" {
  name               = var.auditor_role_suffix
  description        = "Read-only role for compliance evidence collection. Requires MFA on assume."
  assume_role_policy = data.aws_iam_policy_document.auditor_trust.json
  tags               = { Layer = "2-IAM" }
}

resource "aws_iam_role_policy_attachment" "auditor_security_audit" {
  role       = aws_iam_role.auditor.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "auditor_readonly" {
  role       = aws_iam_role.auditor.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

data "aws_iam_policy_document" "admin_trust" {
  statement {
    sid     = "TrustAccountPrincipalsWithMFAAndExternalId"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
    condition {
      test     = "NumericLessThan"
      variable = "aws:MultiFactorAuthAge"
      values   = ["900"]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.admin_role_external_id]
    }
  }
}

resource "aws_iam_role" "admin" {
  #checkov:skip=CKV_AWS_274: Break-glass role; AdministratorAccess is capped by AdminPermissionsBoundary.
  name                 = var.admin_role_suffix
  description          = "Privileged break-glass role. Requires MFA + ExternalId. Capped by AdminPermissionsBoundary."
  assume_role_policy   = data.aws_iam_policy_document.admin_trust.json
  permissions_boundary = aws_iam_policy.admin_boundary.arn
  tags                 = { Layer = "2-IAM" }
}

resource "aws_iam_role_policy_attachment" "admin_administrator" {
  #checkov:skip=CKV_AWS_274: Same as aws_iam_role.admin; attachment is how provider 6 attaches managed policies.
  role       = aws_iam_role.admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
