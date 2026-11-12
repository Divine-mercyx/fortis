resource "aws_s3_bucket" "b0" {
  bucket = "nolt-docs-0"
  acl    = "public-read" # @hit
}

resource "aws_s3_bucket" "b1" {
  bucket = "nolt-docs-1"
  acl    = "public-read-write" # @hit
}

resource "aws_s3_bucket" "b2" {
  bucket = "nolt-docs-2"
  acl    = "authenticated-read" # @hit
}

resource "aws_s3_bucket" "b3" {
  bucket = "nolt-docs-3"
  acl    = "public-read" # @hit
}

resource "aws_s3_bucket" "b4" {
  bucket = "nolt-docs-4"
  acl    = "public-read-write" # @hit
}

resource "aws_s3_bucket_acl" "acl0" {
  bucket = aws_s3_bucket.b0.id
  acl    = "public-read" # @hit
}

resource "aws_s3_bucket_acl" "acl1" {
  bucket = aws_s3_bucket.b1.id
  acl    = "public-read-write" # @hit
}

resource "aws_s3_bucket_public_access_block" "pab0" {
  bucket = aws_s3_bucket.b0.id
  block_public_acls       = false # @hit
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "pab1" {
  bucket = aws_s3_bucket.b1.id
  block_public_acls       = true
  block_public_policy     = false # @hit
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "pab2" {
  bucket = aws_s3_bucket.b2.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = false # @hit
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "pab3" {
  bucket = aws_s3_bucket.b3.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = false # @hit
}

resource "aws_s3_bucket" "private" {
  bucket = "nolt-private"
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "private" {
  bucket                  = aws_s3_bucket.private.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_acl" "logs" {
  bucket = aws_s3_bucket.private.id
  acl    = "log-delivery-write"
}

resource "aws_s3_object" "report" {
  bucket = aws_s3_bucket.private.id
  key    = "report.pdf"
  acl    = "public-read" # @hit
}
