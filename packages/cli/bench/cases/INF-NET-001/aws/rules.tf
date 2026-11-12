resource "aws_security_group_rule" "elastic" {
  type              = "ingress"
  from_port         = 9200
  to_port           = 9200
  protocol          = "tcp"
  ipv6_cidr_blocks  = ["::/0"] # @hit
  security_group_id = aws_security_group.core.id
}

resource "aws_security_group_rule" "mssql" {
  type              = "ingress"
  from_port         = 1433
  to_port           = 1433
  protocol          = "tcp"
  ipv6_cidr_blocks  = ["::/0"] # @hit
  security_group_id = aws_security_group.core.id
}

resource "aws_security_group_rule" "memcached" {
  type              = "ingress"
  from_port         = 11211
  to_port           = 11211
  protocol          = "tcp"
  ipv6_cidr_blocks  = ["::/0"] # @hit
  security_group_id = aws_security_group.core.id
}

resource "aws_security_group_rule" "docker" {
  type              = "ingress"
  from_port         = 2375
  to_port           = 2375
  protocol          = "tcp"
  ipv6_cidr_blocks  = ["::/0"] # @hit
  security_group_id = aws_security_group.core.id
}

resource "aws_security_group_rule" "kubeapi" {
  type              = "ingress"
  from_port         = 6443
  to_port           = 6443
  protocol          = "tcp"
  ipv6_cidr_blocks  = ["::/0"] # @hit
  security_group_id = aws_security_group.core.id
}

resource "aws_security_group_rule" "rabbitmq" {
  type              = "ingress"
  from_port         = 15672
  to_port           = 15672
  protocol          = "tcp"
  ipv6_cidr_blocks  = ["::/0"] # @hit
  security_group_id = aws_security_group.core.id
}

resource "aws_vpc_security_group_ingress_rule" "everything" {
  security_group_id = aws_security_group.core.id
  cidr_ipv4         = "0.0.0.0/0" # @hit
  ip_protocol       = "-1"
}

resource "aws_vpc_security_group_ingress_rule" "range" {
  security_group_id = aws_security_group.core.id
  cidr_ipv4         = "0.0.0.0/0" # @hit
  from_port         = 5000
  to_port           = 6500
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  security_group_id = aws_security_group.core.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_security_group_rule" "egress_ssh" {
  type        = "egress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "admin_from_var" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = var.admin_cidrs
}
