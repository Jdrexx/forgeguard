# ForgeGuard — Terraform Infrastructure
#
# Deploy ForgeGuard to AWS ECS (Fargate) or Railway.
# This module provisions the container infrastructure.
#
# Usage:
#   terraform init
#   terraform plan -out=tfplan
#   terraform apply tfplan

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

  backend "s3" {
    # Configure via backend config or -backend-config flags:
    # bucket = "forgeguard-terraform-state"
    # key    = "forgeguard/terraform.tfstate"
    # region = "us-east-1"
  }
}

provider "aws" {
  region = var.aws_region
}

# ── VPC ────────────────────────────────────────────────────────────────
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name    = "forgeguard-vpc"
    Project = "forgeguard"
  }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name    = "forgeguard-private-${count.index}"
    Project = "forgeguard"
  }
}

resource "aws_subnet" "public" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 10}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false  # ECS tasks run in private subnets; ALB/NAT use dedicated addressing

  tags = {
    Name    = "forgeguard-public-${count.index}"
    Project = "forgeguard"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# ── ECS Cluster ────────────────────────────────────────────────────────
resource "aws_ecs_cluster" "forgeguard" {
  name = "forgeguard-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Project = "forgeguard"
  }
}

# ── IAM ────────────────────────────────────────────────────────────────
resource "aws_iam_role" "ecs_task_execution" {
  name = "forgeguard-ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
  ]
}

resource "aws_iam_role" "ecs_task" {
  name = "forgeguard-ecs-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

# ── ECS Service ────────────────────────────────────────────────────────
resource "aws_ecs_task_definition" "forgeguard" {
  family                   = "forgeguard"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name  = "forgeguard"
      image = "${var.container_image}:${var.container_tag}"
      essential = true
      portMappings = [{
        containerPort = 8000
        protocol      = "tcp"
      }]
      environment = [
        { name = "DEMO_MODE", value = "0" },
        { name = "LOG_LEVEL", value = "info" },
      ]
      healthCheck = {
        command     = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:8000/livez')\""]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 10
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.forgeguard.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "forgeguard"
        }
      }
    }
  ])

  tags = {
    Project = "forgeguard"
  }
}

resource "aws_ecs_service" "forgeguard" {
  name            = "forgeguard-service"
  cluster         = aws_ecs_cluster.forgeguard.id
  task_definition = aws_ecs_task_definition.forgeguard.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = aws_subnet.private[*].id
    security_groups = [aws_security_group.forgeguard.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.forgeguard.arn
    container_name   = "forgeguard"
    container_port   = 8000
  }

  tags = {
    Project = "forgeguard"
  }
}

# ── Load Balancer ──────────────────────────────────────────────────────
resource "aws_lb" "forgeguard" {
  name               = "forgeguard-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  tags = {
    Project = "forgeguard"
  }
}

resource "aws_lb_target_group" "forgeguard" {
  name        = "forgeguard-tg"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path                = "/readyz"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  tags = {
    Project = "forgeguard"
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.forgeguard.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.forgeguard.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.forgeguard.arn
  }
}

# ── Security Groups ────────────────────────────────────────────────────
resource "aws_security_group" "forgeguard" {
  name        = "forgeguard-ecs-sg"
  description = "ForgeGuard ECS tasks"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Project = "forgeguard" }
}

resource "aws_security_group" "alb" {
  name        = "forgeguard-alb-sg"
  description = "ForgeGuard ALB"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Project = "forgeguard" }
}

# ── Logging ────────────────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "forgeguard" {
  name              = "/ecs/forgeguard"
  retention_in_days = 30

  tags = {
    Project = "forgeguard"
  }
}

# ── Variables ──────────────────────────────────────────────────────────
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "container_image" {
  description = "Container image URI"
  type        = string
}

variable "container_tag" {
  description = "Container image tag"
  type        = string
  default     = "latest"
}

variable "certificate_arn" {
  description = "ACM certificate ARN for the HTTPS listener"
  type        = string
}

# ── Outputs ────────────────────────────────────────────────────────────
output "alb_dns_name" {
  value = aws_lb.forgeguard.dns_name
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.forgeguard.name
}

output "ecs_service_name" {
  value = aws_ecs_service.forgeguard.name
}
