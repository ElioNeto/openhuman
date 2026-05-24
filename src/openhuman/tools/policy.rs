//! Runtime policy enforcement, revocation, and audit correlation for
//! generated tools.
//!
//! ## Architecture
//!
//! - [`ToolPattern`] — matches generated tools by provider, capability, or risk level.
//! - [`PolicyAction`] — the action to take when a tool matches: Allow, Deny, or
//!   RequireApproval.
//! - [`GeneratedToolPolicyRule`] — a single policy rule combining a pattern and action.
//! - [`GeneratedToolPolicyEngine`] — resolves rules against the capability provider
//!   registry, evaluates tool execution requests, and produces audit events.
//! - [`ToolExecutionAuditEvent`] — structured audit record correlating provider,
//!   capability, policy decision, approval, and execution outcome.
//!
//! ## Revocation
//!
//! Provider or capability revocation is expressed as a `Deny` rule targeting
//! the provider or a specific capability. Revoked providers can also be
//! marked as disabled in the [`CapabilityProviderRegistry`], which causes the
//! [`AdmissionGate`] to reject any new tools from that provider before they
//! reach the policy engine.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::generated::GeneratedToolDefinition;
use super::provenance::{ToolProvenance, ToolRiskLevel};
use crate::openhuman::capability_provider::{CapabilityProviderRegistry, ProviderId};

// ---------------------------------------------------------------------------
// Tool pattern
// ---------------------------------------------------------------------------

/// Pattern that matches generated tools for policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolPattern {
    /// Matches all tools from a specific provider.
    AllFromProvider(ProviderId),
    /// Matches a specific tool by provider id and capability id.
    SpecificTool {
        provider_id: ProviderId,
        capability_id: String,
    },
    /// Matches all tools at or above the given risk level.
    ByRiskLevel(ToolRiskLevel),
}

impl ToolPattern {
    /// Returns `true` if this pattern matches the given tool definition.
    pub fn matches(&self, provenance: &ToolProvenance) -> bool {
        match self {
            ToolPattern::AllFromProvider(pid) => *pid == provenance.provider_id,
            ToolPattern::SpecificTool {
                provider_id,
                capability_id,
            } => {
                *provider_id == provenance.provider_id
                    && provenance
                        .capability_id
                        .as_deref()
                        .map_or(false, |c| c == capability_id)
            }
            ToolPattern::ByRiskLevel(level) => provenance.risk_level >= *level,
        }
    }
}

// ---------------------------------------------------------------------------
// Policy action
// ---------------------------------------------------------------------------

/// Action to take when a policy rule matches a generated tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    /// Allow execution without additional checks.
    Allow,
    /// Deny execution with a structured reason.
    Deny {
        /// Human-readable reason for the denial.
        reason: String,
    },
    /// Require interactive approval before execution.
    RequireApproval {
        /// Optional reason shown to the user during approval.
        reason: Option<String>,
    },
}

impl PolicyAction {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    /// Return the denial reason, if this is a `Deny` action.
    pub fn denial_reason(&self) -> Option<&str> {
        match self {
            Self::Deny { reason } => Some(reason.as_str()),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Policy rule
// ---------------------------------------------------------------------------

/// A single runtime policy rule for generated tools.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedToolPolicyRule {
    /// Tool name/identifier for diagnostics.
    pub name: String,
    /// Pattern that selects which tools this rule applies to.
    pub pattern: ToolPattern,
    /// Action to take when the pattern matches.
    pub action: PolicyAction,
    /// Optional priority: higher-priority rules are evaluated first.
    /// Default: 0. Rules with the same priority are evaluated in insertion order.
    #[serde(default)]
    pub priority: i32,
}

impl GeneratedToolPolicyRule {
    /// Create a new deny rule for a provider.
    pub fn deny_provider(provider_id: ProviderId, reason: impl Into<String>) -> Self {
        Self {
            name: format!("deny-provider-{}", provider_id),
            pattern: ToolPattern::AllFromProvider(provider_id),
            action: PolicyAction::Deny {
                reason: reason.into(),
            },
            priority: 10,
        }
    }

    /// Create a new deny rule for a specific capability.
    pub fn deny_capability(
        provider_id: ProviderId,
        capability_id: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        let cap = capability_id.into();
        Self {
            name: format!("deny-{}-{}", provider_id, cap),
            pattern: ToolPattern::SpecificTool {
                provider_id,
                capability_id: cap.clone(),
            },
            action: PolicyAction::Deny {
                reason: reason.into(),
            },
            priority: 20,
        }
    }

    /// Create a new allow rule for a provider.
    pub fn allow_provider(provider_id: ProviderId) -> Self {
        Self {
            name: format!("allow-provider-{}", provider_id),
            pattern: ToolPattern::AllFromProvider(provider_id),
            action: PolicyAction::Allow,
            priority: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Policy decision
// ---------------------------------------------------------------------------

/// Result of evaluating policy rules for a tool execution request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    /// Tool is allowed to execute.
    Allowed {
        /// Name of the rule that matched (if any).
        rule_name: Option<String>,
    },
    /// Tool is denied with a reason.
    Denied {
        /// Name of the rule that denied execution.
        rule_name: String,
        /// Human-readable reason for the denial.
        reason: String,
    },
    /// Tool requires interactive approval before execution.
    RequiresApproval {
        /// Name of the rule that requires approval.
        rule_name: String,
        /// Optional reason shown to the user.
        reason: Option<String>,
    },
}

impl PolicyDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    pub fn denial_reason(&self) -> Option<&str> {
        match self {
            Self::Denied { reason, .. } => Some(reason.as_str()),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Execution outcome
// ---------------------------------------------------------------------------

/// Terminal outcome of a tool execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOutcome {
    Success,
    Failure(String),
    Aborted,
}

// ---------------------------------------------------------------------------
// Audit event
// ---------------------------------------------------------------------------

/// Structured audit event for a generated tool execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolExecutionAuditEvent {
    /// ISO-8601 timestamp of the execution.
    pub timestamp: String,
    /// Provider that generated this tool, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    /// Provider-specific capability identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    /// Name of the tool that was executed.
    pub tool_name: String,
    /// Risk level of the tool, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<ToolRiskLevel>,
    /// The policy decision made for this execution.
    pub policy_decision: PolicyDecision,
    /// Approval request id, if approval was required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    /// Terminal outcome of the execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_outcome: Option<ExecutionOutcome>,
}

impl ToolExecutionAuditEvent {
    /// Create a new audit event with the current timestamp.
    pub fn new(tool_name: impl Into<String>) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            provider_id: None,
            capability_id: None,
            tool_name: tool_name.into(),
            risk_level: None,
            policy_decision: PolicyDecision::Allowed { rule_name: None },
            approval_id: None,
            execution_outcome: None,
        }
    }

    /// Attach provenance information from a tool definition.
    pub fn with_provenance(mut self, provenance: Option<&ToolProvenance>) -> Self {
        if let Some(p) = provenance {
            self.provider_id = Some(p.provider_id.to_string());
            self.capability_id = p.capability_id.clone();
            self.risk_level = Some(p.risk_level);
        }
        self
    }

    /// Attach the policy decision.
    pub fn with_decision(mut self, decision: PolicyDecision) -> Self {
        self.policy_decision = decision;
        self
    }

    /// Attach an approval id.
    pub fn with_approval(mut self, approval_id: Option<String>) -> Self {
        self.approval_id = approval_id;
        self
    }

    /// Record the terminal execution outcome.
    pub fn with_outcome(mut self, outcome: ExecutionOutcome) -> Self {
        self.execution_outcome = Some(outcome);
        self
    }
}

// ---------------------------------------------------------------------------
// Policy engine
// ---------------------------------------------------------------------------

/// Runtime policy engine for generated tools.
///
/// Evaluates policy rules against tool execution requests and produces
/// audit events. When enforcement is disabled (default), the engine
/// allows all tools without policy evaluation, maintaining backward
/// compatibility.
#[derive(Debug, Clone)]
pub struct GeneratedToolPolicyEngine {
    rules: Vec<GeneratedToolPolicyRule>,
    provider_registry: CapabilityProviderRegistry,
    enforcement_enabled: bool,
}

impl GeneratedToolPolicyEngine {
    /// Create a new policy engine.
    ///
    /// When `enforcement_enabled` is `false` (default), the engine allows
    /// all tools, bypassing policy evaluation.
    pub fn new(
        rules: Vec<GeneratedToolPolicyRule>,
        provider_registry: CapabilityProviderRegistry,
        enforcement_enabled: bool,
    ) -> Self {
        Self {
            rules,
            provider_registry,
            enforcement_enabled,
        }
    }

    /// Create a permissive engine that allows all tools (default).
    pub fn permissive(provider_registry: CapabilityProviderRegistry) -> Self {
        Self::new(Vec::new(), provider_registry, false)
    }

    /// Evaluate policy for a generated tool execution request.
    ///
    /// Returns the policy decision — `Allowed`, `Denied`, or `RequiresApproval`.
    ///
    /// When enforcement is disabled, always returns `Allowed`.
    /// When the tool has no provenance, also returns `Allowed` (backward
    /// compatibility).
    pub fn evaluate(&self, definition: &GeneratedToolDefinition) -> PolicyDecision {
        // When enforcement is off, always allow.
        if !self.enforcement_enabled {
            return PolicyDecision::Allowed { rule_name: None };
        }

        // Tools without provenance bypass policy when enforcement is off
        // (handled above). If enforcement is on but there's no provenance,
        // the admission gate should have caught this. We allow anyway to
        // avoid breaking existing tools.
        let Some(ref provenance) = definition.provenance else {
            return PolicyDecision::Allowed { rule_name: None };
        };

        // Check provider revocation first: if the provider is not active,
        // deny all its tools.
        if !self.provider_registry.is_active(&provenance.provider_id) {
            return PolicyDecision::Denied {
                rule_name: "provider_revocation".into(),
                reason: format!(
                    "provider `{}` is not active (revoked, disabled, or untrusted)",
                    provenance.provider_id
                ),
            };
        }

        // Evaluate rules in priority order (highest first), then insertion
        // order for equal priorities.
        let mut sorted_rules: Vec<_> = self.rules.iter().enumerate().collect();
        sorted_rules
            .sort_by(|(i_a, a), (i_b, b)| b.priority.cmp(&a.priority).then_with(|| i_a.cmp(i_b)));

        for (_, rule) in &sorted_rules {
            if rule.pattern.matches(provenance) {
                return match &rule.action {
                    PolicyAction::Allow => PolicyDecision::Allowed {
                        rule_name: Some(rule.name.clone()),
                    },
                    PolicyAction::Deny { reason } => PolicyDecision::Denied {
                        rule_name: rule.name.clone(),
                        reason: reason.clone(),
                    },
                    PolicyAction::RequireApproval { reason } => PolicyDecision::RequiresApproval {
                        rule_name: rule.name.clone(),
                        reason: reason.clone(),
                    },
                };
            }
        }

        // No rule matched: allow by default (open policy, subject to
        // admission checks which already verified provider trust).
        PolicyDecision::Allowed { rule_name: None }
    }

    /// Evaluate policy and produce an audit event in one step.
    pub fn evaluate_with_audit(
        &self,
        definition: &GeneratedToolDefinition,
    ) -> (PolicyDecision, ToolExecutionAuditEvent) {
        let decision = self.evaluate(definition);
        let event = ToolExecutionAuditEvent::new(&definition.name)
            .with_provenance(definition.provenance.as_ref())
            .with_decision(decision.clone());
        (decision, event)
    }

    /// Record an execution outcome on an existing audit event.
    pub fn record_execution(
        &self,
        event: &mut ToolExecutionAuditEvent,
        outcome: ExecutionOutcome,
        approval_id: Option<String>,
    ) {
        event.execution_outcome = Some(outcome);
        if let Some(id) = approval_id {
            event.approval_id = Some(id);
        }
    }

    /// Register a new policy rule.
    pub fn add_rule(&mut self, rule: GeneratedToolPolicyRule) {
        self.rules.push(rule);
    }

    /// Remove all rules matching a predicate.
    pub fn remove_rules<F>(&mut self, mut predicate: F)
    where
        F: FnMut(&GeneratedToolPolicyRule) -> bool,
    {
        self.rules.retain(|r| !predicate(r));
    }

    /// Return a reference to all registered rules.
    pub fn rules(&self) -> &[GeneratedToolPolicyRule] {
        &self.rules
    }

    /// Return whether enforcement is enabled.
    pub fn is_enforcement_enabled(&self) -> bool {
        self.enforcement_enabled
    }
}

#[cfg(test)]
#[path = "policy_test.rs"]
mod tests;
