# Layer 5 detection and response (SI-3, SI-4, IR-4, IR-5, IR-6). Always
# managed; the CloudFormation UseExisting switch is not carried. EventBridge
# encrypts both the SNS publish and the DLQ send with the Layer 3 CMK
# (AllowEventBridgeToPublishToEncryptedTopic). LOW and MEDIUM findings stay
# in Security Hub.

resource "aws_sqs_queue" "security_alert_dlq" {
  name                      = "compliance-alert-dlq"
  kms_master_key_id         = aws_kms_key.compliance.arn
  message_retention_seconds = 1209600 # 14 days, the SQS maximum
  tags                      = { Layer = "5-Detection" }
}

data "aws_iam_policy_document" "security_alert_dlq" {
  statement {
    sid    = "AllowEventBridgeToDeadLetter"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.security_alert_dlq.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.high_severity.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "security_alert_dlq" {
  queue_url = aws_sqs_queue.security_alert_dlq.id
  policy    = data.aws_iam_policy_document.security_alert_dlq.json
}

resource "aws_sns_topic" "security_alerts" {
  name              = "compliance-security-alerts"
  display_name      = "Security Alerts (Layer 5)"
  kms_master_key_id = aws_kms_key.compliance.arn
  tags              = { Layer = "5-Detection" }
}

# Stays PendingConfirmation until the recipient clicks the link. Unconfirmed
# subscriptions drop messages, so this path is not live at apply time.
resource "aws_sns_topic_subscription" "security_alerts_email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.security_alert_email
}

data "aws_iam_policy_document" "security_alerts" {
  statement {
    sid    = "AllowEventBridgeToPublish"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.high_severity.arn]
    }
  }
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn    = aws_sns_topic.security_alerts.arn
  policy = data.aws_iam_policy_document.security_alerts.json
}

# CFN-created detectors do not turn on add-on protections. Each feature is
# its own resource because for_each is out of vocabulary. FIFTEEN_MINUTES
# batches updates to existing findings; new findings publish in about five
# minutes either way.
resource "aws_guardduty_detector" "main" {
  #checkov:skip=CKV2_AWS_3: Single-account baseline; org-wide GuardDuty auto-enable is out of scope.
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  tags                         = { Layer = "5-Detection" }
}

resource "aws_guardduty_detector_feature" "s3_data_events" {
  detector_id = aws_guardduty_detector.main.id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}

resource "aws_guardduty_detector_feature" "eks_audit_logs" {
  detector_id = aws_guardduty_detector.main.id
  name        = "EKS_AUDIT_LOGS"
  status      = "ENABLED"
}

resource "aws_guardduty_detector_feature" "ebs_malware_protection" {
  detector_id = aws_guardduty_detector.main.id
  name        = "EBS_MALWARE_PROTECTION"
  status      = "ENABLED"
}

resource "aws_guardduty_detector_feature" "rds_login_events" {
  detector_id = aws_guardduty_detector.main.id
  name        = "RDS_LOGIN_EVENTS"
  status      = "ENABLED"
}

resource "aws_guardduty_detector_feature" "lambda_network_logs" {
  detector_id = aws_guardduty_detector.main.id
  name        = "LAMBDA_NETWORK_LOGS"
  status      = "ENABLED"
}

# severity >= 7 is GuardDuty HIGH (7.0-8.9) and CRITICAL (9.0-10.0).
# The target waits on both policies. Without that, the first finding can
# be denied and also miss the DLQ.
resource "aws_cloudwatch_event_rule" "high_severity" {
  name        = "compliance-high-severity-findings"
  description = "Routes HIGH-severity GuardDuty findings to the security-alert SNS topic (SI-4 / IR-4 / IR-5)."
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [{
        numeric = [">=", 7]
      }]
    }
  })
  tags = { Layer = "5-Detection" }
}

resource "aws_cloudwatch_event_target" "high_severity" {
  rule      = aws_cloudwatch_event_rule.high_severity.name
  target_id = "PublishToAlertTopic"
  arn       = aws_sns_topic.security_alerts.arn
  dead_letter_config {
    arn = aws_sqs_queue.security_alert_dlq.arn
  }
  retry_policy {
    maximum_retry_attempts       = 10
    maximum_event_age_in_seconds = 3600
  }
  depends_on = [
    aws_sns_topic_policy.security_alerts,
    aws_sqs_queue_policy.security_alert_dlq,
  ]
}

# Hub default (EnableDefaultStandards unset in 05-detection.yaml) turns on
# Foundational Security Best Practices and CIS AWS Foundations Benchmark v1.2.0.
# The template's two Standard resources
# are the same NIST ARN under Provision vs UseExisting; UseExisting is dropped.
resource "aws_securityhub_account" "main" {
  enable_default_standards = true
}

resource "aws_securityhub_standards_subscription" "nist_800_53" {
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.region}::standards/nist-800-53/v/5.0.0"
  depends_on    = [aws_securityhub_account.main]
}
