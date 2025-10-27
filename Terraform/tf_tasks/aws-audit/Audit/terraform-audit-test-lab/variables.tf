variable "region" {
  description = "AWS region"
  default     = "us-east-1"
}
# variable "vpc_cidr" {
#   description = "VPC CIDR block"
#   default     = "10.0.0.0/16"
# }


variable "aws_profile" {
  description = "AWS CLI profile to use from ~/.aws/credentials"
  type        = string
  default     = "default"
}
