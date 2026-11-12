variable "allowed" {
  default = ["10.0.0.0/8"]
}

resource "aws_vpc_security_group_ingress_rule" "redis" {
  security_group_id = aws_security_group.cache.id
  cidr_ipv4         = var.allowed_one # @hit
  from_port         = 6379
  to_port           = 6379
  ip_protocol       = "tcp"
}
