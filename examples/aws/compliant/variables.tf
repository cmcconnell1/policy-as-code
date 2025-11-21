variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod"
  }
}

variable "common_tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default = {
    Environment        = "dev"
    CostCenter         = "ENG001"
    Owner              = "devops@example.com"
    Application        = "policy-demo"
    DataClassification = "internal"
    ManagedBy          = "Terraform"
  }
}
