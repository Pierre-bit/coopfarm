terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "3.74.0"
    }
  }
}

# AWS Provider configuration
provider "aws" {
  region                  = "eu-west-3"
  shared_credentials_file = ".aws"
}

# génération des clés
resource "tls_private_key" "algo" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# ajoute les clés au compte AWS
resource "aws_key_pair" "generated_key" {
  key_name = "ssh_key-coopfarm"
  public_key = tls_private_key.algo.public_key_openssh # clé générée à la volée
}

# mappage de ports
resource "aws_security_group" "sg-coopfarm" {

  name = "coopfarm-sg"

  # règle de port entrant
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # règle de port sortant
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # règle de port sortant
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "sg-coopfarm"
  }
}

# vm
resource "aws_instance" "debian10" {
  ami                    = "ami-04e905a52ec8010b2"
  instance_type          = "t2.micro"
  vpc_security_group_ids = [aws_security_group.sg-coopfarm.id] # indique le groupe de sécurité à utiliser
  key_name               = aws_key_pair.generated_key.key_name
  count = 1


  tags = {
    Name = "vm-coopfarm"
  }

   # connection à la vm
   connection {
     type        = "ssh"
     user        = "admin"
     host        = self.public_ip
     private_key = tls_private_key.algo.private_key_pem # clé privée générée à la volée
     timeout = "2m"
   }

   # installe un serveur apach
   provisioner "remote-exec" {
     script = "api_install.sh"
   }
}