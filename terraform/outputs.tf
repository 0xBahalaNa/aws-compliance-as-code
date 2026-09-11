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
