variable "admin_cidrs" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}

variable "office_cidrs" {
  default = ["102.89.10.0/24"]
}

locals {
  everywhere = "0.0.0.0/0"
  pg_port    = 5432
}
