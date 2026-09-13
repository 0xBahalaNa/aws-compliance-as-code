# Layer 1 logging. Multi-region CloudTrail + Object Lock COMPLIANCE bucket +
# VPC Flow Logs (AU-2/3/9/12). CMK on the bucket and both log groups (R-1).

resource "aws_s3_bucket" "cloudtrail_logs" {
  #checkov:skip=CKV_AWS_18: This bucket is the CloudTrail destination; access logging to itself is circular.
  #checkov:skip=CKV_AWS_144: Single-region baseline (R-3); replication is out of scope.
  #checkov:skip=CKV2_AWS_61: 01-logging.yaml has no lifecycle rule; Object Lock COMPLIANCE retains objects 365 days.
  #checkov:skip=CKV2_AWS_62: 01-logging.yaml has no event notifications on the log bucket.
  bucket              = "cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
  object_lock_enabled = true
  tags                = { Layer = "1-Logging" }
  lifecycle { prevent_destroy = true } # CFN DeletionPolicy / UpdateReplacePolicy Retain
}
resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_object_lock_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 365 # CFN S3ObjectLockRetentionDays default; parameter dropped
    }
  }
  depends_on = [aws_s3_bucket_versioning.cloudtrail_logs]
}
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.compliance.arn
    }
    bucket_key_enabled = true
  }
}
resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket                  = aws_s3_bucket.cloudtrail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Statements 1-4 of CloudTrailLogsBucketPolicy. Statement 5
# (DenyBucketConfigTamperingExceptAuditAdmin) waits on M4's bucket_policy_admin role.

data "aws_iam_policy_document" "cloudtrail_logs" {
  statement {
    sid    = "AllowCloudTrailGetBucketAcl"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail_logs.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
  statement {
    sid    = "AllowCloudTrailPutObject"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
  statement {
    sid    = "DenyLogObjectDeletion"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
    resources = ["${aws_s3_bucket.cloudtrail_logs.arn}/*"]
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
      aws_s3_bucket.cloudtrail_logs.arn,
      "${aws_s3_bucket.cloudtrail_logs.arn}/*",
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}
resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_logs.json
}

# CFN used AWS-managed encryption on both groups. CMK now (R-1); the key policy
# grants logs.<region> in 03-encryption.tf Statement 8.

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${var.trail_name}"
  retention_in_days = var.cloudtrail_retention_days
  kms_key_id        = aws_kms_key.compliance.arn
  tags              = { Layer = "1-Logging" }
}
resource "aws_cloudwatch_log_group" "flow_logs" {
  #checkov:skip=CKV_AWS_338: CFN default is 90 days; flow logs are 10-100x CloudTrail volume.
  name              = "/aws/vpc/flowlogs/${var.default_vpc_id}"
  retention_in_days = var.flow_logs_retention_days
  kms_key_id        = aws_kms_key.compliance.arn
  tags              = { Layer = "1-Logging" }
}
data "aws_iam_policy_document" "cloudtrail_to_cloudwatch_assume" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}
data "aws_iam_policy_document" "cloudtrail_to_cloudwatch" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.cloudtrail.arn}:*"]
  }
}
resource "aws_iam_role" "cloudtrail_to_cloudwatch" {
  name               = "cloudtrail-to-cloudwatch"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_to_cloudwatch_assume.json
  tags               = { Layer = "1-Logging" }
}
resource "aws_iam_role_policy" "cloudtrail_to_cloudwatch" {
  name   = "CloudTrailWriteCloudWatchLogs"
  role   = aws_iam_role.cloudtrail_to_cloudwatch.id
  policy = data.aws_iam_policy_document.cloudtrail_to_cloudwatch.json
}

resource "aws_cloudtrail" "main" {
  #checkov:skip=CKV_AWS_252: 01-logging.yaml has no CloudTrail SNS topic; alerting is Layer 5.
  name                          = var.trail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  enable_logging                = true
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.compliance.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_to_cloudwatch.arn
  tags                          = { Layer = "1-Logging" }
  depends_on                    = [aws_s3_bucket_policy.cloudtrail_logs]
}

data "aws_iam_policy_document" "flow_logs_assume" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}
data "aws_iam_policy_document" "flow_logs" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.flow_logs.arn}:*"]
  }
}
resource "aws_iam_role" "flow_logs" {
  name               = "vpc-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume.json
  tags               = { Layer = "1-Logging" }
}
resource "aws_iam_role_policy" "flow_logs" {
  name   = "FlowLogsWriteCloudWatchLogs"
  role   = aws_iam_role.flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs.json
}
resource "aws_flow_log" "default_vpc" {
  vpc_id               = var.default_vpc_id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn         = aws_iam_role.flow_logs.arn
  tags                 = { Layer = "1-Logging" }
}
