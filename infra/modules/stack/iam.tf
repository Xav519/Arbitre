# One role per function in both postures. What changes is the policy attached.
#
#   hardened:   each function gets only the actions and resources its job needs.
#   vulnerable: every function gets the same broad policy, the "one role for the
#               whole app" shortcut. It is broad inside this lab's own resources
#               and never account-wide, so a mistake here cannot reach anything else.

locals {
  table_arn = { for k, t in aws_dynamodb_table.this : k => t.arn }
  bucket    = aws_s3_bucket.data.arn

  llm_arns = [
    "${local.arn_base}:bedrock:${local.region}:${local.account}:inference-profile/${var.model_id}",
    "${local.arn_base}:bedrock:*::foundation-model/${var.foundation_model_id}",
  ]
  embed_arn = "${local.arn_base}:bedrock:${local.region}::foundation-model/${var.embed_model_id}"

  # Listing the public prefix lets S3 answer "no such key" instead of "access denied"
  # for a missing public document. It grants no read on any other prefix.
  list_public = {
    Effect    = "Allow"
    Action    = ["s3:ListBucket"]
    Resource  = [local.bucket]
    Condition = { StringLike = { "s3:prefix" = ["kb/public/*"] } }
  }

  scoped = {
    agent = concat(
      [
        { Effect = "Allow", Action = ["bedrock:InvokeModel"], Resource = local.llm_arns },
        { Effect = "Allow", Action = ["lambda:InvokeFunction"], Resource = [for t, k in local.tool_keys : local.function_arns[k]] },
        { Effect = "Allow", Action = ["dynamodb:GetItem"], Resource = [local.table_arn["customers"]] },
      ],
      local.hardened ? [
        { Effect = "Allow", Action = ["bedrock:ApplyGuardrail"], Resource = [aws_bedrock_guardrail.this[0].guardrail_arn] },
      ] : []
    )

    ingest = [
      { Effect = "Allow", Action = ["s3:GetObject", "s3:DeleteObject"], Resource = ["${local.bucket}/kb/public/*"] },
      { Effect = "Allow", Action = ["s3:PutObject"], Resource = ["${local.bucket}/quarantine/*"] },
      local.list_public,
      { Effect = "Allow", Action = ["kms:Verify"], Resource = [aws_kms_key.signing.arn] },
      { Effect = "Allow", Action = ["dynamodb:Scan", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem"], Resource = [local.table_arn["kb"]] },
      { Effect = "Allow", Action = ["bedrock:InvokeModel"], Resource = [local.embed_arn] },
    ]

    "tool-search-knowledge-base" = [
      { Effect = "Allow", Action = ["dynamodb:Scan"], Resource = [local.table_arn["kb"]] },
      { Effect = "Allow", Action = ["bedrock:InvokeModel"], Resource = [local.embed_arn] },
    ]

    # The internal/ prefix lives in the same bucket. This role cannot read it,
    # whatever key the model asks for.
    "tool-read-document" = [
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = ["${local.bucket}/kb/public/*"] },
      local.list_public,
    ]

    "tool-get-account-summary" = [
      { Effect = "Allow", Action = ["dynamodb:GetItem"], Resource = [local.table_arn["customers"]] },
    ]

    "tool-transfer-funds" = [
      { Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:UpdateItem"], Resource = [local.table_arn["customers"]] },
      { Effect = "Allow", Action = ["dynamodb:PutItem"], Resource = [local.table_arn["transfers"]] },
    ]

    "tool-send-secure-message" = [
      { Effect = "Allow", Action = ["dynamodb:PutItem"], Resource = [local.table_arn["outbox"]] },
    ]
  }

  broad = [
    { Effect = "Allow", Action = ["dynamodb:*"], Resource = values(local.table_arn) },
    { Effect = "Allow", Action = ["s3:*"], Resource = [local.bucket, "${local.bucket}/*"] },
    { Effect = "Allow", Action = ["kms:Sign", "kms:Verify", "kms:GetPublicKey"], Resource = [aws_kms_key.signing.arn] },
    { Effect = "Allow", Action = ["lambda:InvokeFunction"], Resource = ["${local.arn_base}:lambda:${local.region}:${local.account}:function:${local.name}-*"] },
    { Effect = "Allow", Action = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"], Resource = ["*"] },
  ]
}

resource "aws_iam_role" "fn" {
  for_each = local.functions

  name = "${local.function_names[each.key]}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "logs" {
  for_each = local.functions

  name = "logs"
  role = aws_iam_role.fn[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = ["${aws_cloudwatch_log_group.fn[each.key].arn}:*"]
    }]
  })
}

resource "aws_iam_role_policy" "fn" {
  for_each = local.functions

  name = local.hardened ? "least-privilege" : "broad-shared"
  role = aws_iam_role.fn[each.key].id

  policy = local.hardened ? jsonencode({
    Version   = "2012-10-17"
    Statement = local.scoped[each.key]
    }) : jsonencode({
    Version   = "2012-10-17"
    Statement = local.broad
  })
}
