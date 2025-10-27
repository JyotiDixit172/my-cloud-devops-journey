#  Use random suffix automatically 
resource "random_id" "suffix" {
  byte_length = 4
}
resource "aws_s3_bucket" "static_site" {
  #  this way tf will apend random suffix, to avoid conflicts
  bucket = "${var.bucket_name}-${random_id.suffix.hex}"
  tags = {
    Name        = "StaticWebsiteBucket"
    Environment = "Dev"
  }
  #  protect from accidental deletion
  lifecycle {
    prevent_destroy = true
  }
}
# enable Static website hosting
resource "aws_s3_bucket_website_configuration" "static_site" {
  bucket = aws_s3_bucket.static_site.id
  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "error.html"
  }
}
# Allow Public access for Website Hosting (recommended for static sites)
resource "aws_s3_bucket_public_access_block" "static_site" {
  bucket = aws_s3_bucket.static_site.id
  #  this disables the Block Public access settings for one bucket only, so the policy can be applied.
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

#  make objects publicly accessible
resource "aws_s3_bucket_policy" "public_policy" {
  bucket     = aws_s3_bucket.static_site.id
  depends_on = [aws_s3_bucket_public_access_block.static_site]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*" // who will access the resource 
        Action    = ["s3:GetObject"] // what we can do with the resource 
        Resource  = "${aws_s3_bucket.static_site.arn}/*" // which objects/bucket use this policy
      }
    ]
  })
}

#  Life cycle rule - transition to Standard_IA after 30 days
resource "aws_s3_bucket_lifecycle_configuration" "transition_rule" {
  bucket = aws_s3_bucket.static_site.id
  rule {
    id     = "MoveToInfrequentAccess"
    status = "Enabled"
    filter {
      prefix = ""
    }
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
}

# upload index.html
resource "aws_s3_object" "index" {
  bucket       = aws_s3_bucket.static_site.id
  key          = "index.html"
  source       = "${path.module}/site/index.html"
  content_type = "text/html"
}

resource "aws_s3_object" "error" {
  bucket       = aws_s3_bucket.static_site.id
  key          = "error.html"
  source       = "${path.module}/site/error.html"
  content_type = "text/html"
}

#  command to check f bucket name is available before applying run this :
# aws s3api head --bucket my-terraform-static-site-bucket-jyoti-010702
