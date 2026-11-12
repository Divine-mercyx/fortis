resource "google_sql_database_instance" "pg0" {
  name             = "pg-0"
  database_version = "POSTGRES_16"

  settings {
    tier = "db-custom-2-7680"

    ip_configuration {
      ipv4_enabled = true

      authorized_networks {
        name  = "office"
        value = "102.89.0.0/16"
      }

      authorized_networks {
        name  = "anyone"
        value = "0.0.0.0/0" # @hit
      }
    }
  }
}

resource "google_sql_database_instance" "pg1" {
  name             = "pg-1"
  database_version = "POSTGRES_16"

  settings {
    tier = "db-custom-2-7680"

    ip_configuration {
      ipv4_enabled = true

      authorized_networks {
        name  = "office"
        value = "102.89.0.0/16"
      }

      authorized_networks {
        name  = "anyone"
        value = "0.0.0.0/0" # @hit
      }
    }
  }
}

resource "google_sql_database_instance" "pg2" {
  name             = "pg-2"
  database_version = "POSTGRES_16"

  settings {
    tier = "db-custom-2-7680"

    ip_configuration {
      ipv4_enabled = true

      authorized_networks {
        name  = "office"
        value = "102.89.0.0/16"
      }

      authorized_networks {
        name  = "anyone"
        value = "0.0.0.0/0" # @hit
      }
    }
  }
}

resource "google_sql_database_instance" "pg3" {
  name             = "pg-3"
  database_version = "POSTGRES_16"

  settings {
    tier = "db-custom-2-7680"

    ip_configuration {
      ipv4_enabled = true

      authorized_networks {
        name  = "office"
        value = "102.89.0.0/16"
      }

      authorized_networks {
        name  = "anyone"
        value = "0.0.0.0/0" # @hit
      }
    }
  }
}

resource "google_sql_database_instance" "pg4" {
  name             = "pg-4"
  database_version = "POSTGRES_16"

  settings {
    tier = "db-custom-2-7680"

    ip_configuration {
      ipv4_enabled = true

      authorized_networks {
        name  = "office"
        value = "102.89.0.0/16"
      }

      authorized_networks {
        name  = "anyone"
        value = "0.0.0.0/0" # @hit
      }
    }
  }
}

resource "google_sql_database_instance" "pg5" {
  name             = "pg-5"
  database_version = "POSTGRES_16"

  settings {
    tier = "db-custom-2-7680"

    ip_configuration {
      ipv4_enabled = true

      authorized_networks {
        name  = "office"
        value = "102.89.0.0/16"
      }

      authorized_networks {
        name  = "anyone"
        value = "0.0.0.0/0" # @hit
      }
    }
  }
}

resource "google_sql_database_instance" "private" {
  name             = "private"
  database_version = "POSTGRES_16"

  settings {
    tier = "db-custom-2-7680"

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id
    }
  }
}
