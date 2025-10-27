output "application_name" {
    value = var.application_name
}

output "environment_name" {
    value = var.environment_name
}

# output "application_name" {
#   type        = string
#   description = "Name of the application"
# }

# output "environment_name" {
#   type        = string
#   description = "Name of the environment"
# }


output "environment_prefix" {
    value = local.environment_prefix
}

output "suffix"{
    value = random_string.suffix.result
}