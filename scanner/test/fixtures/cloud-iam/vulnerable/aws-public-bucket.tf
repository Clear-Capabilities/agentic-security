resource "aws_iam_role_policy" "public_bucket" {
  name = "public-bucket-policy"
  role = aws_iam_role.example.id

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}
POLICY
}
