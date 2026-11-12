resource "aws_db_instance" "db0" {
  identifier          = "core-0"
  instance_class      = "db.t4g.medium"
  publicly_accessible = true # @hit
}

resource "aws_db_instance" "db1" {
  identifier          = "core-1"
  instance_class      = "db.t4g.medium"
  publicly_accessible = true # @hit
}

resource "aws_rds_cluster_instance" "db2" {
  identifier          = "core-2"
  instance_class      = "db.t4g.medium"
  publicly_accessible = true # @hit
}

resource "aws_redshift_cluster" "db3" {
  identifier          = "core-3"
  instance_class      = "db.t4g.medium"
  publicly_accessible = true # @hit
}

resource "aws_db_instance" "db4" {
  identifier          = "core-4"
  instance_class      = "db.t4g.medium"
  publicly_accessible = true # @hit
}

resource "aws_rds_cluster_instance" "db5" {
  identifier          = "core-5"
  instance_class      = "db.t4g.medium"
  publicly_accessible = true # @hit
}

resource "aws_dms_replication_instance" "db6" {
  identifier          = "core-6"
  instance_class      = "db.t4g.medium"
  publicly_accessible = true # @hit
}

resource "aws_db_instance" "db7" {
  identifier          = "core-7"
  instance_class      = "db.t4g.medium"
  publicly_accessible = true # @hit
}

resource "aws_db_instance" "safe0" {
  identifier          = "safe-0"
  publicly_accessible = false
}

resource "aws_db_instance" "safe1" {
  identifier          = "safe-1"
  publicly_accessible = false
}

resource "aws_db_instance" "safe2" {
  identifier          = "safe-2"
  publicly_accessible = false
}

resource "aws_db_instance" "from_var" {
  identifier          = "configurable"
  publicly_accessible = var.public
}
