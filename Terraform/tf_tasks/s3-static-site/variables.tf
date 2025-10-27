variable "aws_region" {
    description = "AWS region to display resources"
    type = string
    default = "us-east-1"
}

variable "bucket_name" {
    description = "Unique S3 bucket name"
    type = string
    default = "my-terraform-static-site-bucket-jyoti-010702"
}