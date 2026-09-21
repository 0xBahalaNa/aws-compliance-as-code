output "cloudtrail_logs_bucket_name" {
  description = "S3 bucket holding immutable CloudTrail logs."
  value       = aws_s3_bucket.cloudtrail_logs.id
}
output "cloudtrail_logs_bucket_arn" {
  description = "ARN of the CloudTrail logs bucket. BucketPolicyAdminRole is scoped to this."
  value       = aws_s3_bucket.cloudtrail_logs.arn
}
output "cloudtrail_arn" {
  description = "ARN of the multi-region trail."
  value       = aws_cloudtrail.main.arn
}
output "cloudtrail_log_group_arn" {
  description = "CloudWatch Log Group ARN for CloudTrail (metric filters / alarms)."
  value       = aws_cloudwatch_log_group.cloudtrail.arn
}
output "flow_logs_group_arn" {
  description = "CloudWatch Log Group ARN for VPC Flow Logs."
  value       = aws_cloudwatch_log_group.flow_logs.arn
}
output "auditor_role_arn" {
  description = "ARN of the read-only auditor role."
  value       = aws_iam_role.auditor.arn
}
output "admin_role_arn" {
  description = "ARN of the boundary-capped admin role. Break-glass only."
  value       = aws_iam_role.admin.arn
}
output "admin_permissions_boundary_arn" {
  description = "ARN of AdminPermissionsBoundary."
  value       = aws_iam_policy.admin_boundary.arn
}
output "bucket_policy_admin_role_arn" {
  description = "ARN of the CloudTrail bucket-policy carve-out role. Layer 1 DenyBucketConfigTamperingExceptAuditAdmin carves this principal out."
  value       = aws_iam_role.bucket_policy_admin.arn
}
output "bucket_policy_admin_boundary_arn" {
  description = "ARN of BucketPolicyAdminBoundary. Attach to any other principal that must stay inside the 15-action CloudTrail-bucket cap."
  value       = aws_iam_policy.bucket_policy_admin_boundary.arn
}

output "compliance_cmk_arn" {
  description = "ARN of the compliance baseline CMK. Read-out for evidence collection; in-module callers use aws_kms_key.compliance.arn directly."
  value       = aws_kms_key.compliance.arn
}
output "compliance_cmk_id" {
  description = "Key ID of the compliance baseline CMK."
  value       = aws_kms_key.compliance.key_id
}
output "compliance_cmk_alias_name" {
  description = "Alias of the compliance baseline CMK."
  value       = aws_kms_alias.compliance.name
}
