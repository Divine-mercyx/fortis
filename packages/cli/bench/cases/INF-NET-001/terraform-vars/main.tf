resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = var.admin_cidrs # @hit
}

resource "aws_security_group_rule" "pg" {
  type        = "ingress"
  from_port   = local.pg_port
  to_port     = local.pg_port
  protocol    = "tcp"
  cidr_blocks = [local.everywhere] # @hit
}

resource "aws_security_group_rule" "rdp_office" {
  type        = "ingress"
  from_port   = 3389
  to_port     = 3389
  protocol    = "tcp"
  cidr_blocks = var.office_cidrs
}

resource "aws_security_group_rule" "unknown" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = var.from_pipeline
}
