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
          value = "Ov23liZnlg8w1GWaceQE"
        },
        {
          name  = "BACKEND_URL"
          value = "http://secretmgr-nlb-750c1ac03b1b7c1f.elb.us-west-1.amazonaws.com:8000"
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

