# Deliberately insecure Terraform used to verify the gate fails as expected.
# Do not use as a reference: every block here is a known misconfiguration.

resource "aws_s3_bucket" "data" {
  bucket = "ra-demo-bucket"
}

# Public access is explicitly allowed (should be blocked).
resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# SSH open to the whole internet.
resource "aws_security_group" "open" {
  name = "ra-demo-open"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
