# terraform >= 1.9, aws >= 6.22.0 (matches aws-grc-terraform-modules). Local state.

terraform {
  required_version = ">= 1.9"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.22.0"
    }
  }
}
