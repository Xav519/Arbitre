output "region" {
  value = local.region
}

output "mode" {
  value = var.mode
}

output "controls_override" {
  value = var.controls_override
}

output "model_id" {
  value = var.model_id
}

output "agent_function" {
  value = aws_lambda_function.fn["agent"].function_name
}

output "ingest_function" {
  value = aws_lambda_function.fn["ingest"].function_name
}

output "customers_table" {
  value = aws_dynamodb_table.this["customers"].name
}

output "transfers_table" {
  value = aws_dynamodb_table.this["transfers"].name
}

output "outbox_table" {
  value = aws_dynamodb_table.this["outbox"].name
}

output "kb_table" {
  value = aws_dynamodb_table.this["kb"].name
}

output "bucket" {
  value = aws_s3_bucket.data.id
}

output "signing_key_id" {
  value = aws_kms_key.signing.key_id
}

output "guardrail_id" {
  value = local.hardened ? aws_bedrock_guardrail.this[0].guardrail_id : ""
}

output "alarm_topic_arn" {
  value = aws_sns_topic.security.arn
}
