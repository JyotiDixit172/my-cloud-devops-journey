resource "random_string" "suffix" {
    length = 6
    upper = false
    special = false
}

locals {
    environment_prefix = "${var.application_name}-${var.environment_name}"
}