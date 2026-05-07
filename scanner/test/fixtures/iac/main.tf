resource "aws_s3_bucket" "logs" {
  bucket = "my-app-logs"
  acl    = "public-read"
}

resource "aws_iam_policy" "all" {
  policy = jsonencode({
    Statement = [{
      Action = "*"
      Effect = "Allow"
      Resource = "*"
    }]
  })
}

resource "aws_db_instance" "db" {
  encrypted = false
}
