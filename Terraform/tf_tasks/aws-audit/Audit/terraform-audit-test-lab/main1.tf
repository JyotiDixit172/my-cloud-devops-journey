# -----------------------
# IAM Section
# -----------------------

# IAM User without MFA (FAIL)
resource "aws_iam_user" "user_without_mfa" {
  name = "audit-user-no-mfa"
}

# IAM User with Access Key (FAIL if unused/stale)
resource "aws_iam_access_key" "user_key" {
  user = aws_iam_user.user_without_mfa.name
}

# Account Password Policy (PASS)
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length      = 14
  require_symbols              = true
  require_numbers              = true
  require_uppercase_characters = true
  require_lowercase_characters = true
  password_reuse_prevention    = 24
  max_password_age             = 90
}

# -----------------------
# VPC (PASS)
# -----------------------

# Create a VPC
resource "aws_vpc" "audit_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "audit-vpc"
  }
}

# Create an Internet Gateway for public access
resource "aws_internet_gateway" "audit_igw" {
  vpc_id = aws_vpc.audit_vpc.id

  tags = {
    Name = "audit-igw"
  }
}

# Create a public subnet
resource "aws_subnet" "audit_subnet" {
  vpc_id                  = aws_vpc.audit_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "audit-subnet"
  }
}

# Create a route table
resource "aws_route_table" "audit_rt" {
  vpc_id = aws_vpc.audit_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.audit_igw.id
  }

  tags = {
    Name = "audit-rt"
  }
}

# Associate subnet with route table
resource "aws_route_table_association" "audit_rta" {
  subnet_id      = aws_subnet.audit_subnet.id
  route_table_id = aws_route_table.audit_rt.id
}


# -----------------------
# EC2 + Security Groups
# -----------------------

# Security Group allowing 0.0.0.0/0 on SSH (FAIL)
resource "aws_security_group" "sg_open_ssh" {
  name        = "open-ssh" # as sg can't be prefix in name of resource, as AWS reserves it for it's own generated IDs.
  description = "Open SSH for audit fail test"
  vpc_id      = aws_vpc.audit_vpc.id # <--  replace with your VPC ID

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Security Group with restricted access (PASS)
resource "aws_security_group" "sg_restricted" {
  name        = "restricted-sg" # same as above comment in sg_open_ssh resource
  description = "Restricted SG for audit pass test"
  vpc_id      = aws_vpc.audit_vpc.id # <-- replace with your VPC ID

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"] # Fake office IP range
  }
}

# EC2 Instance without IMDSv2 (FAIL)
resource "aws_instance" "ec2_fail" {
  ami                    = "ami-0c02fb55956c7d316" # Amazon Linux 2 (us-east-1)
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.audit_subnet.id # <-- replace with your subnet ID
  vpc_security_group_ids = [aws_security_group.sg_open_ssh.id]

  metadata_options {
    http_tokens = "optional" # FAIL (should be required)
  }
}

# -----------------------
# S3 Buckets
# -----------------------

# Public S3 Bucket without encryption (FAIL)
resource "aws_s3_bucket" "bucket_public" {
  bucket = "audit-lab-public-${random_integer.rand.result}"
  # acl    = "public-read" # will trigger FAIL in audit
}


resource "aws_s3_bucket_policy" "public_policy" {
  bucket = aws_s3_bucket.bucket_public.id

  policy = <<EOT
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::${aws_s3_bucket.bucket_public.id}/*"
    }
  ]
}
EOT
}


# # #  prevents S3 depricated warning dues to HCL version conventions
# resource "aws_s3_bucket_acl" "public_acl" {
#   bucket = aws_s3_bucket.bucket_public.id
#   acl    = "public-read" # will trigger FAIL in audit
#   # (see a yellow warning safe to ignore for learning/demo)
#   # it's just terraform's way of nudging you towards best practices
# }

# # Disable Block Public Access so the ACL can take effect (only for demo!)
# #  S3 bucket ACLs (access denied fix)
# resource "aws_s3_bucket_public_access_block" "disable_block" {
#   bucket = aws_s3_bucket.bucket_public.id

#   block_public_acls       = true
#   ignore_public_acls      = true
#   block_public_policy     = false
#   restrict_public_buckets = false
# }


# Encrypted S3 Bucket (PASS)
resource "aws_s3_bucket" "bucket_encrypted" {
  bucket = "audit-lab-encrypted-${random_integer.rand.result}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "encrypted" {
  bucket = aws_s3_bucket.bucket_encrypted.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# -----------------------
# RDS Instance
# -----------------------

# Public RDS Instance (FAIL)
resource "aws_db_instance" "rds_fail" {
  identifier          = "audit-rds-fail"
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = "password123!"
  skip_final_snapshot = true
  publicly_accessible = true # FAIL
}

# -----------------------
# Random Integer for unique bucket names
# -----------------------
resource "random_integer" "rand" {
  min = 1000
  max = 9999
}
