terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

locals {
  primary_subnet_id = element(data.aws_subnets.default.ids, 0)
}

resource "aws_ecr_repository" "api" {
  name         = "secretmgr-api"
  force_delete = true

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_secretsmanager_secret" "app" {
  name                    = "secretmgr/app"
  recovery_window_in_days = 0
}

resource "aws_iam_role" "ecs_task_execution" {
  name = "secretmgr-ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role" "ecs_task" {
  name = "secretmgr-ecs-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "ecs_execution_secret_access" {
  name = "secretmgr-execution-secret-access"
  role = aws_iam_role.ecs_task_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue"
        ]
        Resource = aws_secretsmanager_secret.app.arn
      }
    ]
  })
}

resource "aws_iam_role_policy" "secret_access" {
  name = "secretmgr-secret-access"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = aws_secretsmanager_secret.app.arn
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/ecs/secretmgr-api"
  retention_in_days = 7
}

resource "aws_security_group" "api" {
  name        = "secretmgr-sg"
  description = "Allow inbound access to the secret manager API container"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "HTTP access for API container"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.default.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_eip" "lb" {
  domain = "vpc"
}

resource "aws_lb" "api" {
  name               = "secretmgr-nlb"
  load_balancer_type = "network"

  subnet_mapping {
    subnet_id     = local.primary_subnet_id
    allocation_id = aws_eip.lb.allocation_id
  }
}

resource "aws_lb_target_group" "api" {
  name        = "secretmgr-tg"
  port        = 8000
  protocol    = "TCP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default.id
}

resource "aws_lb_listener" "api" {
  load_balancer_arn = aws_lb.api.arn
  port              = 8000
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

resource "aws_ecs_cluster" "main" {
  name = "secretmgr-cluster"
}

resource "aws_ecs_task_definition" "api" {
  family                   = "secretmgr-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name      = "api"
      image     = "${aws_ecr_repository.api.repository_url}:latest"
      essential = true
      environment = [
        {
          name  = "OAUTH_ID_GITHUB"
          value = var.oauth_client_id
        },
        {
          # Must match what clients actually call, because GitHub redirects the
          # OAuth callback here. With HTTPS on, that is the CloudFront hostname.
          name  = "BACKEND_URL"
          value = local.api_base_url
        },
        {
          name  = "ENABLE_TEST_LOGIN"
          value = var.enable_test_login ? "true" : "false"
        }
      ]
      portMappings = [
        {
          containerPort = 8000
          hostPort      = 8000
          protocol      = "tcp"
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.api.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "ecs"
        }
      }
      secrets = [
        {
          name      = "OAUTH_SECRET_GITHUB"
          valueFrom = aws_secretsmanager_secret.app.arn
        },
        {
          # Populate this secret with a Fernet key before deploying, otherwise
          # the service falls back to storing secret values in plaintext:
          #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
          name      = "SECRET_ENCRYPTION_KEY"
          valueFrom = aws_secretsmanager_secret.encryption_key.arn
        }
      ]
    }
  ])
}

resource "aws_ecs_service" "api" {
  name            = "secretmgr-api"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  depends_on      = [aws_lb_listener.api]

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "api"
    container_port   = 8000
  }

  network_configuration {
    subnets          = [local.primary_subnet_id]
    security_groups  = [aws_security_group.api.id]
    assign_public_ip = true
  }
}


# --------------------------------------------------------------------------
# HTTPS
#
# The NLB speaks plain TCP on port 8000, so clients would otherwise send their
# GitHub token and every secret value across the internet in the clear.
# CloudFront terminates TLS using its own free *.cloudfront.net certificate,
# which needs no domain and therefore works for any deployment of this project.
#
# The CloudFront-to-origin hop stays HTTP. It runs over the AWS backbone rather
# than the public internet, but it is not encrypted: closing that gap needs a
# certificate the origin can present, which needs a domain you control. Set
# domain_name and acm_certificate_arn if you have one.
# --------------------------------------------------------------------------

locals {
  # AWS-managed policies. An API must not be cached, and it needs the viewer's
  # Authorization header forwarded or every request arrives unauthenticated.
  cloudfront_caching_disabled_policy_id       = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
  cloudfront_all_viewer_except_host_policy_id = "b689b0a8-53d0-40ab-baf2-68738e2966ac"

  api_origin_id = "secretmgr-nlb-origin"

  api_base_url = var.enable_https ? (
    var.domain_name != "" ? "https://${var.domain_name}" : "https://${aws_cloudfront_distribution.api[0].domain_name}"
  ) : "http://${aws_lb.api.dns_name}:8000"
}

resource "aws_cloudfront_distribution" "api" {
  count = var.enable_https ? 1 : 0

  enabled         = true
  comment         = "HTTPS entrypoint for the secret manager API"
  is_ipv6_enabled = true
  price_class     = "PriceClass_100"

  aliases = var.domain_name != "" ? [var.domain_name] : []

  origin {
    domain_name = aws_lb.api.dns_name
    origin_id   = local.api_origin_id

    custom_origin_config {
      http_port                = 8000
      https_port               = 443
      origin_protocol_policy   = "http-only"
      origin_ssl_protocols     = ["TLSv1.2"]
      origin_read_timeout      = 30
      origin_keepalive_timeout = 5
    }
  }

  default_cache_behavior {
    target_origin_id       = local.api_origin_id
    viewer_protocol_policy = "redirect-to-https"

    allowed_methods = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods  = ["GET", "HEAD"]

    cache_policy_id          = local.cloudfront_caching_disabled_policy_id
    origin_request_policy_id = local.cloudfront_all_viewer_except_host_policy_id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = var.domain_name == ""
    acm_certificate_arn            = var.domain_name != "" ? var.acm_certificate_arn : null
    ssl_support_method             = var.domain_name != "" ? "sni-only" : null
    minimum_protocol_version       = var.domain_name != "" ? "TLSv1.2_2021" : null
  }

  lifecycle {
    precondition {
      condition     = var.domain_name == "" || var.acm_certificate_arn != ""
      error_message = "domain_name requires acm_certificate_arn (issued in us-east-1)."
    }
  }
}

# Key used to encrypt secret values before they reach the database. Kept
# separate from the OAuth secret so it can be rotated independently.
resource "aws_secretsmanager_secret" "encryption_key" {
  name                    = "secretmgr/encryption-key"
  description             = "Fernet key used to encrypt secret values at rest"
  recovery_window_in_days = 7
}

resource "aws_iam_role_policy" "encryption_key_access" {
  name = "secretmgr-encryption-key-access"
  role = aws_iam_role.ecs_task_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue"
        ]
        Resource = aws_secretsmanager_secret.encryption_key.arn
      }
    ]
  })
}
