# Amazon Bedrock Guardrails, hardened posture only. The orchestrator calls it
# through ApplyGuardrail at three points: user input, retrieved documents, and
# the final answer.

resource "aws_bedrock_guardrail" "this" {
  count = local.hardened ? 1 : 0

  name                      = local.name
  description               = "InnovaBank hardened assistant: prompt attack, sensitive data and topic policy"
  blocked_input_messaging   = "I can't help with that request."
  blocked_outputs_messaging = "I can't share that information."

  content_policy_config {
    filters_config {
      type            = "PROMPT_ATTACK"
      input_strength  = "HIGH"
      output_strength = "NONE"
    }
    filters_config {
      type            = "MISCONDUCT"
      input_strength  = "HIGH"
      output_strength = "HIGH"
    }
  }

  sensitive_information_policy_config {
    pii_entities_config {
      type   = "CA_SOCIAL_INSURANCE_NUMBER"
      action = "BLOCK"
    }
    pii_entities_config {
      type   = "CREDIT_DEBIT_CARD_NUMBER"
      action = "BLOCK"
    }
    pii_entities_config {
      type   = "AWS_SECRET_KEY"
      action = "BLOCK"
    }
    regexes_config {
      name        = "internal-api-key"
      description = "InnovaBank internal API key format"
      pattern     = "ibk_(live|test)_[A-Za-z0-9]{12,}"
      action      = "BLOCK"
    }
    regexes_config {
      name        = "prompt-leak-canary"
      description = "Canary embedded in the system prompt to make leaks detectable"
      pattern     = "IB-LEAK-CANARY-[A-Z0-9]+"
      action      = "BLOCK"
    }
  }

  topic_policy_config {
    topics_config {
      name       = "investment-advice"
      type       = "DENY"
      definition = "Recommendations to buy, sell or hold specific stocks, funds, cryptocurrencies or other investments."
      examples = [
        "Which stock should I buy this week?",
        "Should I move my savings into crypto?",
      ]
    }
  }
}

resource "aws_bedrock_guardrail_version" "this" {
  count = local.hardened ? 1 : 0

  guardrail_arn = aws_bedrock_guardrail.this[0].guardrail_arn
  description   = "Managed by Terraform"
}
