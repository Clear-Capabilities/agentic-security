resource "aws_iam_role" "app" {
  name = "app-${var.suffix}"
  assume_role_policy = file("${path.module}/trust.json")
}
