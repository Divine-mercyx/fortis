# resource "aws_security_group_rule" "old" {
#   type        = "ingress"
#   from_port   = 22
#   to_port     = 22
#   cidr_blocks = ["0.0.0.0/0"]
# }

/*
resource "aws_security_group_rule" "older" {
  type        = "ingress"
  from_port   = 5432
  to_port     = 5432
  cidr_blocks = ["0.0.0.0/0"]
}
*/

resource "aws_security_group_rule" "bastion" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"] # fortis-ignore: bastion host, key-only SSH with fail2ban
}
