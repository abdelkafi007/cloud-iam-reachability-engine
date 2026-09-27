terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true

  endpoints {
    iam = "http://127.0.0.1:5000"
    s3  = "http://127.0.0.1:5000"
  }
}

resource "aws_iam_user" "bob" {
  name = "bob"
}

resource "aws_iam_policy" "wildcard_admin" {
  name        = "TerraformFullAdmin"
  description = "A Dangerous admin policy created via IaC"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "bob_admin_attach" {
  user       = aws_iam_user.bob.name
  policy_arn = aws_iam_policy.wildcard_admin.arn
}

resource "aws_iam_user" "charlie" {
  name = "charlie"
}
resource "aws_iam_policy" "privilage_escalaion" {
  name        = "escalation"
  description = "using this policy to elevate the privilage to root"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow",
        Action = "iam:CreateAccessKey",
        Resource = "arn:aws:iam::123456789012:user/admin"
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "charli_admin" {
  user = aws_iam_user.charlie.name
  policy_arn = aws_iam_policy.privilage_escalaion.arn
}
resource "aws_iam_user" "admin" {
  name = "admin"
}

resource "aws_iam_user_policy_attachment" "admin_attach" {
  user       = aws_iam_user.admin.name
  policy_arn = aws_iam_policy.wildcard_admin.arn
}