# InnovaBank, vulnerable posture. Deploy with: make deploy-vulnerable

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.6.0"
    }
  }
}

variable "region" {
  description = "AWS Region. Must offer the Bedrock models in supplychain/model-lock.yaml."
  type        = string
  default     = "us-east-1"
}

variable "alarm_email" {
  description = "Optional address for security alarm notifications."
  type        = string
  default     = ""
}

variable "controls_override" {
  description = "Optional control ablation, for example \"-taint_lock\"."
  type        = string
  default     = ""
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project = "innovabank"
      Posture = "vulnerable"
      Purpose = "ai-security-lab"
    }
  }
}

module "stack" {
  source = "../../modules/stack"

  mode              = "vulnerable"
  alarm_email       = var.alarm_email
  controls_override = var.controls_override
}

output "region" { value = module.stack.region }
output "mode" { value = module.stack.mode }
output "controls_override" { value = module.stack.controls_override }
output "model_id" { value = module.stack.model_id }
output "agent_function" { value = module.stack.agent_function }
output "ingest_function" { value = module.stack.ingest_function }
output "customers_table" { value = module.stack.customers_table }
output "transfers_table" { value = module.stack.transfers_table }
output "outbox_table" { value = module.stack.outbox_table }
output "kb_table" { value = module.stack.kb_table }
output "bucket" { value = module.stack.bucket }
output "signing_key_id" { value = module.stack.signing_key_id }
output "guardrail_id" { value = module.stack.guardrail_id }
output "alarm_topic_arn" { value = module.stack.alarm_topic_arn }
