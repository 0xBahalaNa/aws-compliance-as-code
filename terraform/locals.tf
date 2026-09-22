# Shared names and the one 15-action S3 list (#24 / #48).
# admin_boundary_name is the single literal for name + Deny ARN (#23).
locals {
  admin_boundary_name               = "compliance-admin-boundary"
  bucket_policy_admin_boundary_name = "compliance-bucket-policy-admin-boundary"
  bucket_policy_admin_actions = [
    "s3:GetBucketPolicy",
    "s3:PutBucketPolicy",
    "s3:DeleteBucketPolicy",
    "s3:PutBucketAcl",
    "s3:PutBucketPublicAccessBlock",
    "s3:PutEncryptionConfiguration",
    "s3:PutBucketObjectLockConfiguration",
    "s3:PutLifecycleConfiguration",
    "s3:PutBucketVersioning",
    "s3:PutBucketCORS",
    "s3:PutBucketNotification",
    "s3:PutBucketLogging",
    "s3:PutReplicationConfiguration",
    "s3:PutBucketTagging",
    "s3:PutBucketOwnershipControls",
  ]
}
