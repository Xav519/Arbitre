# Account-level Bedrock model invocation logging. Optional, and applied once per
# Region, not once per stack. Deploy with: make deploy-account
#
# With text delivery on, full prompts and completions are written to the log
# group below. In this lab that is synthetic data. In a real account it is
# customer data, so restrict who can read this log group accordingly.

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project = "innovabank"
      Purpose = "ai-security-lab"
    }
  }
}

data "aws_caller_identity" "current" {}

resource "aws_cloudwatch_log_group" "invocations" {
  #checkov:skip=CKV_AWS_338:Optional lab logging, 14 days is enough to inspect a run; it holds prompts, so shorter is better
  #checkov:skip=CKV_AWS_158:Service-managed encryption; the log is removed with terraform destroy after the lab
  name              = "/innovabank/bedrock/model-invocations"
  retention_in_days = 14
}

resource "aws_iam_role" "bedrock_logging" {
  name = "innovabank-bedrock-invocation-logging"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "bedrock.amazonaws.com" }
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:aws:bedrock:${var.region}:${data.aws_caller_identity.current.account_id}:*" }
      }
    }]
  })
}

resource "aws_iam_role_policy" "bedrock_logging" {
  name = "write-invocation-logs"
  role = aws_iam_role.bedrock_logging.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = ["${aws_cloudwatch_log_group.invocations.arn}:log-stream:aws/bedrock/modelinvocations"]
    }]
  })
}

resource "aws_bedrock_model_invocation_logging_configuration" "this" {
  logging_config {
    text_data_delivery_enabled      = true
    image_data_delivery_enabled     = false
    embedding_data_delivery_enabled = false

    cloudwatch_config {
      log_group_name = aws_cloudwatch_log_group.invocations.name
      role_arn       = aws_iam_role.bedrock_logging.arn
    }
  }

  depends_on = [aws_iam_role_policy.bedrock_logging]
}

resource "aws_cloudwatch_query_definition" "invocations_by_identity" {
  name            = "InnovaBank/bedrock invocations by caller and model"
  log_group_names = [aws_cloudwatch_log_group.invocations.name]

  query_string = <<-EOT
    fields @timestamp, identity.arn, modelId, operation, input.inputTokenCount, output.outputTokenCount
    | stats count() as calls, sum(input.inputTokenCount) as input_tokens, sum(output.outputTokenCount) as output_tokens by identity.arn, modelId
    | sort calls desc
  EOT
}
