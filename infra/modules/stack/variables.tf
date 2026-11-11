variable "mode" {
  description = "Security posture of this stack: vulnerable or hardened."
  type        = string

  validation {
    condition     = contains(["vulnerable", "hardened"], var.mode)
    error_message = "mode must be vulnerable or hardened."
  }
}

variable "name_prefix" {
  description = "Prefix for every resource name."
  type        = string
  default     = "innovabank"
}

variable "controls_override" {
  description = "Optional control ablation, for example \"-taint_lock,-tool_policy\". Empty uses the preset for the mode."
  type        = string
  default     = ""
}

variable "model_id" {
  description = "Bedrock inference profile or model id the agent calls. Must be listed in supplychain/model-lock.yaml."
  type        = string
  default     = "us.amazon.nova-lite-v1:0"
}

variable "foundation_model_id" {
  description = "Foundation model behind model_id, used to scope IAM."
  type        = string
  default     = "amazon.nova-lite-v1:0"
}

variable "embed_model_id" {
  description = "Bedrock embedding model for the knowledge base."
  type        = string
  default     = "amazon.titan-embed-text-v2:0"
}

variable "alarm_email" {
  description = "Optional address subscribed to the security alarm topic."
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the stack's functions."
  type        = number
  default     = 14
}
