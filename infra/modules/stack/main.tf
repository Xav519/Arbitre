data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  name     = "${var.name_prefix}-${var.mode}"
  hardened = var.mode == "hardened"
  account  = data.aws_caller_identity.current.account_id
  region   = data.aws_region.current.name
  arn_base = "arn:${data.aws_partition.current.partition}"

  tools = [
    "search_knowledge_base",
    "read_document",
    "get_account_summary",
    "transfer_funds",
    "send_secure_message",
  ]

  # tool name -> function key, for example transfer_funds -> tool-transfer-funds
  tool_keys = { for t in local.tools : t => "tool-${replace(t, "_", "-")}" }

  functions = merge(
    {
      agent  = { handler = "innovabank.handlers.agent_handler", timeout = 300, memory = 512 }
      ingest = { handler = "innovabank.handlers.ingest_handler", timeout = 60, memory = 256 }
    },
    { for t, k in local.tool_keys : k => { handler = "innovabank.handlers.tool_handler", timeout = 30, memory = 256 } }
  )

  function_names = { for k, _ in local.functions : k => "${local.name}-${k}" }
  function_arns  = { for k, n in local.function_names : k => "${local.arn_base}:lambda:${local.region}:${local.account}:function:${n}" }

  tables = {
    customers = "customer_id"
    transfers = "transfer_id"
    outbox    = "message_id"
    kb        = "chunk_id"
  }

  environment = {
    IB_MODE              = var.mode
    IB_CONTROLS          = var.controls_override
    IB_MODEL_ID          = var.model_id
    IB_EMBED_MODEL_ID    = var.embed_model_id
    IB_GUARDRAIL_ID      = local.hardened ? aws_bedrock_guardrail.this[0].guardrail_id : ""
    IB_GUARDRAIL_VERSION = local.hardened ? aws_bedrock_guardrail_version.this[0].version : ""
    IB_CUSTOMERS_TABLE   = aws_dynamodb_table.this["customers"].name
    IB_TRANSFERS_TABLE   = aws_dynamodb_table.this["transfers"].name
    IB_OUTBOX_TABLE      = aws_dynamodb_table.this["outbox"].name
    IB_KB_TABLE          = aws_dynamodb_table.this["kb"].name
    IB_BUCKET            = aws_s3_bucket.data.id
    IB_SIGNING_KEY_ID    = aws_kms_key.signing.key_id
    IB_TOOL_FUNCTIONS    = jsonencode({ for t, k in local.tool_keys : t => local.function_names[k] })
  }
}

# ----------------------------------------------------------------------------- storage

resource "aws_s3_bucket" "data" {
  bucket_prefix = "${local.name}-"
  force_destroy = true # lab stack, torn down between demos
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "tls_only" {
  bucket = aws_s3_bucket.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.data.arn, "${aws_s3_bucket.data.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })

  depends_on = [aws_s3_bucket_public_access_block.data]
}

resource "aws_dynamodb_table" "this" {
  for_each = local.tables

  name         = "${local.name}-${each.key}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = each.value

  attribute {
    name = each.value
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }
}

# Asymmetric key for knowledge base documents. Publishers hold kms:Sign.
# The ingestion function holds kms:Verify and nothing else on this key.
resource "aws_kms_key" "signing" {
  description              = "${local.name} knowledge base document signing"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  deletion_window_in_days  = 7
}

resource "aws_kms_alias" "signing" {
  name          = "alias/${local.name}-kb-signing"
  target_key_id = aws_kms_key.signing.key_id
}

# ----------------------------------------------------------------------------- functions

data "archive_file" "app" {
  type        = "zip"
  source_dir  = "${path.module}/../../../app"
  output_path = "${path.module}/.build/app-${var.mode}.zip"
  excludes    = ["**/__pycache__/**"]
}

resource "aws_cloudwatch_log_group" "fn" {
  for_each = local.functions

  name              = "/aws/lambda/${local.function_names[each.key]}"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "fn" {
  for_each = local.functions

  function_name    = local.function_names[each.key]
  role             = aws_iam_role.fn[each.key].arn
  runtime          = "python3.13"
  architectures    = ["arm64"]
  handler          = each.value.handler
  timeout          = each.value.timeout
  memory_size      = each.value.memory
  filename         = data.archive_file.app.output_path
  source_code_hash = data.archive_file.app.output_base64sha256

  environment {
    variables = local.environment
  }

  depends_on = [aws_cloudwatch_log_group.fn, aws_iam_role_policy.fn]
}

# New public documents are ingested as they land.
resource "aws_lambda_permission" "s3_ingest" {
  statement_id   = "AllowS3Invoke"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.fn["ingest"].function_name
  principal      = "s3.amazonaws.com"
  source_arn     = aws_s3_bucket.data.arn
  source_account = local.account
}

resource "aws_s3_bucket_notification" "ingest" {
  bucket = aws_s3_bucket.data.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.fn["ingest"].arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "kb/public/"
  }

  depends_on = [aws_lambda_permission.s3_ingest]
}
