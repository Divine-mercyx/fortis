resource "google_storage_bucket_iam_member" "m0" {
  bucket = google_storage_bucket.statements.name
  role   = "roles/storage.objectViewer"
  member = "allUsers" # @hit
}

resource "google_storage_bucket_iam_member" "m1" {
  bucket = google_storage_bucket.statements.name
  role   = "roles/storage.objectViewer"
  member = "allAuthenticatedUsers" # @hit
}

resource "google_storage_bucket_iam_member" "m2" {
  bucket = google_storage_bucket.statements.name
  role   = "roles/storage.objectViewer"
  member = "allUsers" # @hit
}

resource "google_storage_bucket_iam_binding" "binding" {
  bucket  = google_storage_bucket.kyc.name
  role    = "roles/storage.objectViewer"
  members = ["serviceAccount:api@nolt.iam.gserviceaccount.com", "allUsers"] # @hit
}

resource "google_storage_bucket_iam_member" "team" {
  bucket = google_storage_bucket.kyc.name
  role   = "roles/storage.objectAdmin"
  member = "group:platform@nolt.example"
}

resource "google_storage_bucket_access_control" "public" {
  bucket = google_storage_bucket.assets.name
  role   = "READER"
  entity = "allUsers" # @hit
}
