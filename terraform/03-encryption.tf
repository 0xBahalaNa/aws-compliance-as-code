# Layer 3 encryption. Agency-managed CMK (CJIS v6.1 SC-28(1); SC-12 / SC-13 /
# SC-28). prevent_destroy = CFN DeletionPolicy/UpdateReplacePolicy Retain.

resource "aws_kms_key" "compliance" {
  description              = "Compliance baseline CMK. Encrypts CloudTrail logs (S3) and EBS volumes at rest. NIST 800-53 SC-12 / SC-13 / SC-28; CJIS v6.1 SC-28(1)."
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage                = "ENCRYPT_DECRYPT"
  multi_region             = false # at-rest is per-region
  deletion_window_in_days  = var.pending_deletion_window_days
  enable_key_rotation      = true # SC-12 annual rotation; id/ARN/alias stay
  policy                   = data.aws_iam_policy_document.compliance_cmk.json
  tags                     = { Layer = "3-Encryption" }
  lifecycle { prevent_destroy = true }
}

data "aws_iam_policy_document" "compliance_cmk" {
  #checkov:skip=CKV_AWS_109: KMS key policies require Resource "*" because the policy is attached to this key.
  #checkov:skip=CKV_AWS_111: KMS key policies require Resource "*" because the policy is attached to this key.
  #checkov:skip=CKV_AWS_356: KMS key policies require Resource "*" because the policy is attached to this key.
  policy_id = "compliance-baseline-cmk-policy"

  # Statement 1: IAM-delegation switch. Key policy is ROOT OF TRUST; IAM
  # kms:Decrypt does nothing unless this allows it. ":root" = the ACCOUNT.
  # Removing this can permanently orphan the key. Kept by design.
  statement {
    sid       = "EnableIamPolicyDelegation"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  # Statement 2: KEY ADMINISTRATOR in the key policy (SC-12). Omits Encrypt /
  # Decrypt / GenerateDataKey, but kms:Create* also matches kms:CreateGrant, so
  # this role can grant itself Decrypt. Administration is separated from use by
  # convention here, not by the key policy. Faithful port; the CFN says the same
  # at 03-encryption.yaml:109-111.
  statement {
    sid    = "AllowKeyAdministration"
    effect = "Allow"
    actions = [
      "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*",
      "kms:Update*", "kms:Revoke*", "kms:Disable*", "kms:Get*", "kms:Delete*",
      "kms:TagResource", "kms:UntagResource", "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion", "kms:RotateKeyOnDemand",
    ]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [var.key_administrator_role_arn]
    }
  }

  # Statement 3: CloudTrail KEY USER (envelope encryption). aws:SourceAccount is the confused-deputy guard.
  statement {
    sid       = "AllowCloudTrailToEncryptLogs"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  # Statement 4 (AllowKeyUsage: Decrypt + DescribeKey for the auditor role,
  # AC-6) lands in M3. The CFN took that principal as a KeyUserRoleArns
  # parameter; the port drops the parameter and references the role resource
  # directly, so the statement waits on aws_iam_role.auditor rather than on an
  # ARN an operator would otherwise hand-supply twice.

  # Statement 5: SNS service principal (Layer 5 alert topic). Confused-deputy guard: aws:SourceAccount.
  statement {
    sid       = "AllowSnsServiceUsage"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  # Statement 6: SQS service principal (Layer 5 DLQ). Same guard as Statement 5.
  statement {
    sid       = "AllowSqsServiceUsage"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["sqs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  # Statement 7: GuardDuty Malware Protection. Scans need CreateGrant + Decrypt
  # + GenerateDataKeyWithoutPlaintext once this CMK is the EBS default. Without
  # this, SI-3 is enabled-but-inoperative. aws:SourceAccount blocks other SLRs.
  statement {
    sid       = "AllowGuardDutyMalwareProtection"
    effect    = "Allow"
    actions   = ["kms:CreateGrant", "kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKeyWithoutPlaintext"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["malware-protection.guardduty.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

# Callers use the alias so the key id can change underneath.
resource "aws_kms_alias" "compliance" {
  name          = var.key_alias_name
  target_key_id = aws_kms_key.compliance.key_id
}

# Native EBS defaults replace the Lambda custom resource. Both are account
# settings, not data: destroying aws_ebs_default_kms_key resets the default
# to the AWS-managed EBS key (a CJIS SC-28(1) regression), so terraform
# destroy is a deliberate decommission, not routine. No prevent_destroy here:
# key_arn is ForceNew, so it would also block repointing the default at a new
# CMK, which the CFN custom resource handled in place. The CMK's own
# prevent_destroy is what protects key material.
resource "aws_ebs_encryption_by_default" "compliance" {
  enabled = true
}

resource "aws_ebs_default_kms_key" "compliance" {
  key_arn = aws_kms_key.compliance.arn
}
