output "instance_id" {
  description = "ID of the EC2 instance running the API."
  value       = aws_instance.api.id
}

output "public_ip" {
  description = "Public IP address of the EC2 instance."
  value       = aws_instance.api.public_ip
}

output "ecr_repo_url" {
  description = "URL of the ECR repository."
  value       = aws_ecr_repository.api.repository_url
}

output "secret_arn" {
  description = "ARN of the Secrets Manager secret."
  value       = aws_secretsmanager_secret.app.arn
}

