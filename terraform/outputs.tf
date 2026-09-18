output "ecs_cluster_arn" {
  description = "ARN of the ECS cluster running the API."
  value       = aws_ecs_cluster.main.arn
}

output "ecs_service_name" {
  description = "Name of the ECS service running the API."
  value       = aws_ecs_service.api.name
}

output "ecs_task_definition_arn" {
  description = "ARN of the ECS task definition for the API."
  value       = aws_ecs_task_definition.api.arn
}

output "ecr_repo_url" {
  description = "URL of the ECR repository."
  value       = aws_ecr_repository.api.repository_url
}

output "secret_arn" {
  description = "ARN of the Secrets Manager secret."
  value       = aws_secretsmanager_secret.app.arn
}

output "load_balancer_ip" {
  description = "Static public IP address of the Network Load Balancer."
  value       = aws_eip.lb.public_ip
}


output "api_base_url" {
  description = "Base URL clients should use. Set the CLI's BACKEND_URL to this."
  value       = local.api_base_url
}

output "cloudfront_domain_name" {
  description = "CloudFront hostname serving the API over HTTPS, when enabled."
  value       = var.enable_https ? aws_cloudfront_distribution.api[0].domain_name : null
}

output "encryption_key_secret_arn" {
  description = "Secrets Manager entry holding the at-rest encryption key. Populate it with a Fernet key."
  value       = aws_secretsmanager_secret.encryption_key.arn
}
