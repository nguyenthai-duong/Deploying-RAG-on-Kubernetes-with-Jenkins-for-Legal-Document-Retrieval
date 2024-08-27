terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "4.80.0"  # Provider version
    }
  }
  required_version = ">= 1.7.5"  # Terraform version
}

# The provider block to configure Google Cloud
provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# Google Kubernetes Engine Cluster
resource "google_container_cluster" "my_gke" {
  name                      = "${var.project_id}-gke-1"
  location                  = var.region
  remove_default_node_pool  = true
  initial_node_count        = 1
  node_locations            = [var.zone]
}

# Google Kubernetes Engine Node Pool
resource "google_container_node_pool" "primary_preemptible_nodes" {
  name       = "primary-node-pool"
  location   = var.region
  cluster    = google_container_cluster.my_gke.name
  node_count = 1

  node_config {
    preemptible  = false
    machine_type = "e2-standard-4"  
  }
}


