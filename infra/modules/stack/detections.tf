# Detections. Every control decision in the application is logged as one JSON
# line with a `ib_event` field. Each event below becomes a CloudWatch metric and
# an alarm whose description carries the MITRE ATLAS technique and the OWASP LLM
# category, so whoever is on call starts with the mapping already done.
#
# The checks run in both postures. In the vulnerable stack they log
# action="observed" (nothing is stopped), in the hardened stack action="blocked".
# The alarms fire either way.
#
# Keep this table in sync with app/innovabank/seclog.py. A unit test enforces it.

locals {
  detections = {
    prompt_injection           = { atlas = "AML.T0051.000", technique = "LLM Prompt Injection: Direct", owasp = "LLM01", source = "agent", threshold = 3 }
    prompt_obfuscation         = { atlas = "AML.T0068", technique = "LLM Prompt Obfuscation", owasp = "LLM01", source = "agent", threshold = 1 }
    indirect_injection         = { atlas = "AML.T0051.001", technique = "LLM Prompt Injection: Indirect", owasp = "LLM01", source = "agent", threshold = 1 }
    rag_document_rejected      = { atlas = "AML.T0070", technique = "RAG Poisoning", owasp = "LLM04", source = "ingest", threshold = 1 }
    tool_call_denied           = { atlas = "AML.T0053", technique = "AI Agent Tool Invocation", owasp = "LLM06", source = "agent", threshold = 3 }
    exfiltration_attempt       = { atlas = "AML.T0086", technique = "Exfiltration via AI Agent Tool Invocation", owasp = "LLM06", source = "agent", threshold = 1 }
    system_prompt_leak         = { atlas = "AML.T0056", technique = "Extract LLM System Prompt", owasp = "LLM07", source = "agent", threshold = 1 }
    sensitive_data_in_output   = { atlas = "AML.T0057", technique = "LLM Data Leakage", owasp = "LLM02", source = "agent", threshold = 1 }
    unsafe_output_rendering    = { atlas = "AML.T0077", technique = "LLM Response Rendering", owasp = "LLM05", source = "agent", threshold = 1 }
    poisoned_content_in_output = { atlas = "AML.T0070", technique = "RAG Poisoning", owasp = "LLM04", source = "agent", threshold = 1 }
    resource_budget_exceeded   = { atlas = "AML.T0029", technique = "Denial of AI Service", owasp = "LLM10", source = "agent", threshold = 5 }
    guardrail_intervened       = { atlas = "AML.T0054", technique = "LLM Jailbreak", owasp = "LLM01", source = "agent", threshold = 3 }
    tool_access_denied         = { atlas = "AML.T0053", technique = "AI Agent Tool Invocation", owasp = "LLM06", source = "agent", threshold = 1 }
  }

  metric_namespace = "InnovaBank/${var.mode}"
}

resource "aws_cloudwatch_log_metric_filter" "detection" {
  for_each = local.detections

  name           = "${local.name}-${each.key}"
  log_group_name = aws_cloudwatch_log_group.fn[each.value.source].name
  pattern        = "{ $.ib_event = \"${each.key}\" }"

  metric_transformation {
    name          = each.key
    namespace     = local.metric_namespace
    value         = "1"
    default_value = "0"
  }
}

resource "aws_sns_topic" "security" {
  #checkov:skip=CKV_AWS_26:CloudWatch alarms cannot publish to a topic encrypted with the AWS managed key (see below)
  # Not encrypted with alias/aws/sns on purpose: CloudWatch alarms cannot publish
  # to a topic that uses the AWS managed key. Alarm text holds no customer data.
  name = "${local.name}-security-alarms"
}

resource "aws_sns_topic_subscription" "email" {
  count = var.alarm_email == "" ? 0 : 1

  topic_arn = aws_sns_topic.security.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

resource "aws_cloudwatch_metric_alarm" "detection" {
  for_each = local.detections

  alarm_name          = "${local.name}-${each.key}"
  alarm_description   = "MITRE ATLAS ${each.value.atlas} ${each.value.technique} | OWASP ${each.value.owasp} | posture ${var.mode} | event ${each.key}"
  namespace           = local.metric_namespace
  metric_name         = each.key
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security.arn]

  tags = {
    "mitre-atlas" = each.value.atlas
    "owasp-llm"   = each.value.owasp
  }

  depends_on = [aws_cloudwatch_log_metric_filter.detection]
}

resource "aws_cloudwatch_query_definition" "by_technique" {
  name = "InnovaBank/${var.mode}/security events by ATLAS technique"

  log_group_names = [
    aws_cloudwatch_log_group.fn["agent"].name,
    aws_cloudwatch_log_group.fn["ingest"].name,
  ]

  query_string = <<-EOT
    fields @timestamp, ib_event, atlas_technique, owasp, control, action, customer_id, detail
    | filter ispresent(ib_event)
    | stats count() as events by atlas_technique, atlas_name, owasp, control, action
    | sort events desc
  EOT
}

resource "aws_cloudwatch_query_definition" "timeline" {
  name = "InnovaBank/${var.mode}/attack timeline for one request"

  log_group_names = [aws_cloudwatch_log_group.fn["agent"].name]

  query_string = <<-EOT
    fields @timestamp, request_id, ib_event, atlas_technique, control, action, detail
    | filter ispresent(ib_event)
    | sort @timestamp asc
    | limit 200
  EOT
}
