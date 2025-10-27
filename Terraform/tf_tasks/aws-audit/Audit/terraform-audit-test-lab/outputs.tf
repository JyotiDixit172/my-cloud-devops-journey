output "s3_public_bucket" {
  value = aws_s3_bucket.bucket_public.bucket
}

output "s3_encrypted_bucket" {
  value = aws_s3_bucket.bucket_encrypted.bucket
}

output "ec2_instance_id" {
  value = aws_instance.ec2_fail.id
}

output "rds_endpoint" {
  value = aws_db_instance.rds_fail.endpoint
}
