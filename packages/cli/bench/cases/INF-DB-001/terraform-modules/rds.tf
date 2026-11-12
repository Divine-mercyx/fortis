variable "public" {
  default = true
}

module "core" {
  source              = "terraform-aws-modules/rds/aws"
  identifier          = "core"
  publicly_accessible = true # @hit
}

module "ledger" {
  source              = "terraform-aws-modules/rds-aurora/aws"
  publicly_accessible = var.public # @hit
}

module "replica" {
  source              = "terraform-aws-modules/rds/aws"
  publicly_accessible = false
}
