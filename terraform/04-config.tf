# Layer 4 configuration compliance (CM-2, CM-6, CM-8, SC-7). Recorder, delivery
# channel, and six managed rules that check Layers 1-3. Always managed; the
# CloudFormation UseExisting switch is not carried.

resource "aws_s3_bucket" "config" {
  #checkov:skip=CKV_AWS_18: This bucket is the Config delivery destination; access logging to itself is circular.
  #checkov:skip=CKV_AWS_144: Single-region baseline (R-3); replication is out of scope.
  #checkov:skip=CKV2_AWS_61: 04-config.yaml has no lifecycle rule; Object Lock COMPLIANCE retains objects.
  #checkov:skip=CKV2_AWS_62: 04-config.yaml has no event notifications on the delivery bucket.
  # Region in the name: one recorder per region, so a second region must not collide.
  bucket              = "aws-config-${data.aws_region.current.region}-${data.aws_caller_identity.current.account_id}"
  object_lock_enabled = true
  tags                = { Layer = "4-Config" }
  lifecycle { prevent_destroy = true } # CFN DeletionPolicy / UpdateReplacePolicy Retain
}
resource "aws_s3_bucket_versioning" "config" {
  bucket = aws_s3_bucket.config.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_object_lock_configuration" "config" {
  bucket = aws_s3_bucket.config.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.config_bucket_object_lock_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.config]
}
resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.compliance.arn
    }
    bucket_key_enabled = true
  }
}
resource "aws_s3_bucket_public_access_block" "config" {
  bucket                  = aws_s3_bucket.config.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# No s3:x-amz-acl condition. BucketOwnerEnforced rejects ACL headers, and
# Config stopped sending one. Confused-deputy guard is aws:SourceAccount.

data "aws_iam_policy_document" "config_bucket" {
  statement {
    sid    = "AllowConfigGetBucketAcl"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
  statement {
    sid    = "AllowConfigListBucket"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.config.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
  statement {
    sid    = "AllowConfigPutObject"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
  statement {
    sid    = "DenyObjectDeletion"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
    resources = ["${aws_s3_bucket.config.arn}/*"]
  }
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.config.arn,
      "${aws_s3_bucket.config.arn}/*",
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}
resource "aws_s3_bucket_policy" "config" {
  bucket = aws_s3_bucket.config.id
  policy = data.aws_iam_policy_document.config_bucket.json
}

data "aws_iam_policy_document" "config_recorder_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

# Delivery writes and CMK use. The key policy's IAM-delegation statement is
# what lets this role call kms:GenerateDataKey on aws_kms_key.compliance.
data "aws_iam_policy_document" "config_delivery" {
  statement {
    sid       = "WriteDeliveryObjects"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"]
  }
  statement {
    sid       = "ReadBucketMetadata"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.config.arn]
  }
  statement {
    sid    = "EncryptDeliveryObjectsWithCmk"
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.compliance.arn]
  }
}
resource "aws_iam_role" "config_recorder" {
  name               = "config-recorder"
  assume_role_policy = data.aws_iam_policy_document.config_recorder_trust.json
  tags               = { Layer = "4-Config" }
}
resource "aws_iam_role_policy" "config_delivery" {
  name   = "ConfigDeliveryAndEncryption"
  role   = aws_iam_role.config_recorder.id
  policy = data.aws_iam_policy_document.config_delivery.json
}
resource "aws_iam_role_policy_attachment" "config_recorder" {
  role       = aws_iam_role.config_recorder.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "main" {
  name     = "compliance-recorder"
  role_arn = aws_iam_role.config_recorder.arn
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

# PutDeliveryChannel checks that the role can write the bucket. CloudFormation
# puts the inline policy on the role resource; Terraform splits it, so name
# those resources here or the channel can be created before the role can write.
resource "aws_config_delivery_channel" "main" {
  name           = "compliance-channel"
  s3_bucket_name = aws_s3_bucket.config.id
  snapshot_delivery_properties {
    delivery_frequency = var.config_snapshot_delivery_frequency
  }
  depends_on = [
    aws_config_configuration_recorder.main,
    aws_s3_bucket_policy.config,
    aws_iam_role_policy.config_delivery,
    aws_iam_role_policy_attachment.config_recorder,
    aws_s3_bucket_server_side_encryption_configuration.config,
  ]
}

# aws_config_configuration_recorder does not start recording. This does,
# after the channel exists.
resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

resource "aws_config_config_rule" "multi_region_cloudtrail" {
  name                        = "multi-region-cloudtrail-enabled"
  description                 = "Verifies at least one multi-region CloudTrail is enabled (CM-6, Layer 1)."
  maximum_execution_frequency = "One_Hour"
  source {
    owner             = "AWS"
    source_identifier = "MULTI_REGION_CLOUD_TRAIL_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "s3_encryption_enabled" {
  name        = "s3-bucket-server-side-encryption-enabled"
  description = "Verifies S3 buckets have default encryption enabled (CM-6, lax check)."
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }
  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "s3_kms_encryption" {
  name        = "s3-default-encryption-kms"
  description = "Verifies S3 buckets default to SSE-KMS rather than SSE-S3 (CM-6). The AWS-managed aws/s3 key still passes."
  source {
    owner             = "AWS"
    source_identifier = "S3_DEFAULT_ENCRYPTION_KMS"
  }
  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

# Character-class flags are literals: 02-iam-baseline.tf hardcodes them true.
# The three numbers are the same variables the password policy uses.
resource "aws_config_config_rule" "iam_password_policy" {
  name                        = "iam-password-policy"
  description                 = "Verifies the account password policy matches the Layer 2 baseline (CM-6 / IA-5)."
  maximum_execution_frequency = "One_Hour"
  input_parameters = jsonencode({
    RequireUppercaseCharacters = "true"
    RequireLowercaseCharacters = "true"
    RequireSymbols             = "true"
    RequireNumbers             = "true"
    MinimumPasswordLength      = tostring(var.minimum_password_length)
    PasswordReusePrevention    = tostring(var.password_reuse_prevention)
    MaxPasswordAge             = tostring(var.max_password_age_days)
  })
  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "encrypted_volumes" {
  name        = "encrypted-volumes"
  description = "Verifies attached EBS volumes are encrypted (CM-6 / SC-28, Layer 3)."
  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }
  scope {
    compliance_resource_types = ["AWS::EC2::Volume"]
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_config_rule" "restricted_ssh" {
  name        = "restricted-ssh"
  description = "Verifies security groups do not allow unrestricted SSH (SC-7 / CM-6)."
  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }
  scope {
    compliance_resource_types = ["AWS::EC2::SecurityGroup"]
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}
