resource "google_compute_firewall" "open_0" {
  name          = "open-0"
  network       = google_compute_network.vpc.name
  source_ranges = ["0.0.0.0/0"] # @hit

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "open_1" {
  name          = "open-1"
  network       = google_compute_network.vpc.name
  source_ranges = ["0.0.0.0/0"] # @hit

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }
}

resource "google_compute_firewall" "open_2" {
  name          = "open-2"
  network       = google_compute_network.vpc.name
  source_ranges = ["0.0.0.0/0"] # @hit

  allow {
    protocol = "tcp"
    ports    = ["5432", "6379"]
  }
}

resource "google_compute_firewall" "open_3" {
  name          = "open-3"
  network       = google_compute_network.vpc.name
  source_ranges = ["0.0.0.0/0"] # @hit

  allow {
    protocol = "tcp"
    ports    = ["27000-28000"]
  }
}

resource "google_compute_firewall" "web" {
  name          = "web"
  network       = google_compute_network.vpc.name
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }
}

resource "google_compute_firewall" "iap_ssh" {
  name          = "iap-ssh"
  network       = google_compute_network.vpc.name
  source_ranges = ["35.235.240.0/20"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "egress" {
  name               = "egress"
  network            = google_compute_network.vpc.name
  direction          = "EGRESS"
  destination_ranges = ["0.0.0.0/0"]
  source_ranges      = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["5432"]
  }
}
