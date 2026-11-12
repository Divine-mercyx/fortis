module "bastion_sg" {
  source              = "terraform-aws-modules/security-group/aws"
  name                = "bastion"
  ingress_cidr_blocks = ["0.0.0.0/0"] # @hit
  ingress_rules       = ["ssh-tcp"]
}

module "db_sg" {
  source = "terraform-aws-modules/security-group/aws"
  name   = "db"
  ingress_with_cidr_blocks = [
    {
      from_port   = 5432
      to_port     = 5432
      protocol    = "tcp"
      cidr_blocks = "0.0.0.0/0" # @hit
    },
    {
      rule        = "mongodb-27017-tcp"
      cidr_blocks = "10.0.0.0/16"
    },
    {
      rule        = "rdp-tcp"
      cidr_blocks = "0.0.0.0/0" # @hit
    },
  ]
}

module "alb_sg" {
  source              = "terraform-aws-modules/security-group/aws"
  ingress_cidr_blocks = ["0.0.0.0/0"]
  ingress_rules       = ["https-443-tcp", "http-80-tcp"]
}
