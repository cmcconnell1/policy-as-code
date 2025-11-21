# Example: Non-compliant AWS configuration
# This configuration FAILS multiple policy checks
# Use this to test that policies are working correctly

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# VIOLATION: Missing encryption
# VIOLATION: Missing required tags
# VIOLATION: Public ACL
resource "aws_s3_bucket" "insecure" {
  bucket = "my-insecure-bucket"
  acl    = "public-read"

  tags = {
    Name = "test-bucket"
  }
}

# VIOLATION: Security group allows SSH from 0.0.0.0/0
resource "aws_security_group" "insecure_sg" {
  name        = "insecure-sg"
  description = "Insecure security group for testing"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "All ports from anywhere"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# VIOLATION: Unencrypted EBS volume
# VIOLATION: Missing required tags
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 100

  tags = {
    Name = "unencrypted-volume"
  }
}

# VIOLATION: RDS with default port (security risk)
# VIOLATION: No multi-AZ for prod (FFIEC)
# VIOLATION: No backups (SOX)
# VIOLATION: Unencrypted storage
resource "aws_db_instance" "insecure_db" {
  identifier           = "insecure-database"
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "hardcoded_password_bad!" # VIOLATION: Hardcoded password
  port                 = 3306                      # VIOLATION: Default port
  publicly_accessible  = true                      # VIOLATION: Publicly accessible
  storage_encrypted    = false                     # VIOLATION: Not encrypted
  multi_az             = false                     # VIOLATION: No multi-AZ
  backup_retention_period = 0                      # VIOLATION: No backups

  skip_final_snapshot = true

  tags = {
    Name        = "test-db"
    Environment = "prod" # Tagged as prod but violates prod requirements
  }
}

# VIOLATION: Oversized instance type (cost governance)
# VIOLATION: Prohibited instance family
resource "aws_instance" "expensive" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "p3.16xlarge" # VIOLATION: GPU instance, very expensive

  tags = {
    Name = "expensive-instance"
  }
}

# VIOLATION: IAM user instead of role (SOX)
resource "aws_iam_user" "service_account" {
  name = "service-account"

  tags = {
    Purpose = "Application service account"
  }
}

# VIOLATION: Overly permissive IAM policy
# VIOLATION: No MFA requirement for privileged access
resource "aws_iam_policy" "admin_access" {
  name        = "overly-permissive"
  description = "Policy with admin access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*:*"
      Resource = "*"
    }]
  })
}

# VIOLATION: VPC without flow logs (FFIEC)
resource "aws_vpc" "no_monitoring" {
  cidr_block = "10.1.0.0/16"

  tags = {
    Name = "no-flow-logs"
  }
}
