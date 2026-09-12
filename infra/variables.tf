variable "aws_region" {
  description = "Region to deploy into. Use us-east-1 if you want AWS Health (exposed credential) events, which are delivered there for global services such as IAM."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix for all resource names."
  type        = string
  default     = "key-remediation"
}

variable "lambda_runtime" {
  description = "Lambda Python runtime. Must match a version tested in CI."
  type        = string
  default     = "python3.12"

  validation {
    condition     = contains(["python3.12", "python3.13"], var.lambda_runtime)
    error_message = "lambda_runtime must be python3.12 or python3.13."
  }
}

variable "lambda_timeout_seconds" {
  description = "Lambda timeout. Two IAM calls should finish well under 10 seconds."
  type        = number
  default     = 30
}

variable "lambda_reserved_concurrency" {
  description = "Caps concurrent executions. This is a blast-radius control: a flood of findings (or an attacker abusing the trigger) cannot deactivate keys faster than this. Set to -1 to disable the cap."
  type        = number
  default     = 2
}

variable "log_retention_days" {
  description = "CloudWatch log retention for the Lambda."
  type        = number
  default     = 90
}

variable "enable_guardduty_trigger" {
  description = "Create the EventBridge rule that invokes the Lambda on GuardDuty IAM access key findings."
  type        = bool
  default     = true
}

variable "guardduty_min_severity" {
  description = "Only GuardDuty findings with severity >= this value trigger remediation. GuardDuty scale: Low 1-3.9, Medium 4-6.9, High 7-8.9, Critical 9+."
  type        = number
  default     = 7

  validation {
    condition     = var.guardduty_min_severity >= 0 && var.guardduty_min_severity <= 10
    error_message = "guardduty_min_severity must be between 0 and 10."
  }
}

variable "guardduty_finding_types" {
  description = "GuardDuty finding type prefixes that trigger remediation. Only findings whose resource is an IAM user access key are ever matched, regardless of this list."
  type        = list(string)
  default = [
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
    "UnauthorizedAccess:IAMUser/TorIPCaller",
    "CredentialAccess:IAMUser/AnomalousBehavior",
    "Recon:IAMUser/MaliciousIPCaller",
    "Recon:IAMUser/TorIPCaller",
    "PenTest:IAMUser/",
    "Exfiltration:IAMUser/AnomalousBehavior",
    "Persistence:IAMUser/AnomalousBehavior",
    "PrivilegeEscalation:IAMUser/AnomalousBehavior",
  ]
}

variable "exempt_user_names" {
  description = "IAM user names whose keys must never be auto-deactivated (break-glass accounts, CI deployers you would rather page a human for). Applied at the EventBridge rule, so the Lambda is never invoked for them."
  type        = list(string)
  default     = []
}

variable "enable_health_trigger" {
  description = "Create the EventBridge rule that invokes the Lambda when AWS Health reports a credential as exposed (e.g. found on public GitHub). Requires aws_region = us-east-1."
  type        = bool
  default     = true
}

variable "enable_guardduty_detector" {
  description = "Create a GuardDuty detector in this account/region. Leave false if GuardDuty is already enabled (it is a per-account singleton) or if you do not want the cost."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Extra tags applied to every resource."
  type        = map(string)
  default     = {}
}
