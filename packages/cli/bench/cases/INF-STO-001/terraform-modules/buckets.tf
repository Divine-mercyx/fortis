module "public_docs" {
  source = "terraform-aws-modules/s3-bucket/aws"
  bucket = "nolt-public-docs"
  acl    = "public-read" # @hit
}

module "statements" {
  source                  = "terraform-aws-modules/s3-bucket/aws"
  bucket                  = "nolt-statements"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = false # @hit
  restrict_public_buckets = true
}

module "private" {
  source = "terraform-aws-modules/s3-bucket/aws"
  bucket = "nolt-private"
  acl    = "private"
}
