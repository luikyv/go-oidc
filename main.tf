terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.50" }
  }
}

provider "aws" {
  region = var.region
  profile = "personal"
}

######################### Variables #########################

variable "region"        {
    type = string
    default = "us-east-1"
}
variable "go_oidc_domain"  {
    type = string
    default = "goidc.luikyv.com"
}
variable "go_oidc_matls_domain"  {
    type = string
    default = "matls-goidc.luikyv.com"
}
variable "repo_url"      {
    type = string
    default = "https://github.com/luikyv/go-oidc.git"
}
variable "repo_branch"   {
    type = string
    default = "certification"
}

######################### Data #########################

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["137112412989"] # Amazon
  filter {
    name = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

data "aws_vpc" "default" { default = true }

data "aws_route53_zone" "luikyv" {
  name         = "luikyv.com."
  private_zone = false
}

data "aws_ec2_managed_prefix_list" "eic" {
  name = "com.amazonaws.${var.region}.ec2-instance-connect"
}

######################### Resources #########################

resource "aws_security_group" "go_oidc" {
  name        = "go-oidc-sg"
  description = "Allow HTTPS only"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    prefix_list_ids  = [data.aws_ec2_managed_prefix_list.eic.id]
    description      = "SSH from AWS EC2 Instance Connect service only"
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "go-oidc-certification" }
}

resource "aws_instance" "go_oidc" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.go_oidc.id]
  associate_public_ip_address = true

  root_block_device {
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
  }

  user_data = <<-EOF
    #!/bin/bash
    set -eux
    dnf -y update
    dnf -y install ec2-instance-connect git tar golang
    systemctl enable --now sshd

    git clone --branch ${var.repo_branch} ${var.repo_url} /home/ec2-user/go-oidc
    chown -R ec2-user:ec2-user /home/ec2-user/go-oidc
  EOF

  tags = { Name = "go-oidc-certification" }
}

resource "aws_eip" "ip" {
  domain   = "vpc"
  instance = aws_instance.go_oidc.id
  tags = { Name = "go-oidc-certification" }
}

resource "aws_route53_record" "go_oidc" {
  zone_id = data.aws_route53_zone.luikyv.zone_id
  name    = "goidc.luikyv.com"
  type    = "A"
  ttl     = 60
  records = [aws_eip.ip.public_ip]
}

resource "aws_route53_record" "go_oidc_matls" {
  zone_id = data.aws_route53_zone.luikyv.zone_id
  name    = "matls-goidc.luikyv.com"
  type    = "A"
  ttl     = 60
  records = [aws_eip.ip.public_ip]
}

######################### Outputs #########################

output "public_ip" { value = aws_eip.ip.public_ip }

output "urls" {
  value = ["https://${var.go_oidc_domain}", "https://${var.go_oidc_matls_domain}"]
}
