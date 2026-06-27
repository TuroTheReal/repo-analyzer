# Deliberately insecure Terraform (demo fixture) for the IaC domain.

resource "aws_s3_bucket" "data" {
  bucket = "ra-critical-bucket"
}

resource "aws_security_group" "open" {
  name = "ra-critical-open"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
