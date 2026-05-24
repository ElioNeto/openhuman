use serde_json::json;

use super::*;
use crate::openhuman::capability_provider::{CapabilityProvider, ProviderEnabledState};
use crate::openhuman::tools::generated::GeneratedToolDefinition;
use crate::openhuman::tools::provenance::{PolicySurface, ToolProvenance};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn trusted_registry() -> CapabilityProviderRegistry {
    let mut registry = CapabilityProviderRegistry::empty();
    registry.register(CapabilityProvider::trusted("trusted-provider", "Trusted Provider").unwrap());
    registry.register(CapabilityProvider::trusted("another-provider", "Another Provider").unwrap());
    registry
}

fn sample_definition(provenance: Option<ToolProvenance>) -> GeneratedToolDefinition {
    GeneratedToolDefinition {
        name: "send_update".into(),
        description: "Send a scoped update.".into(),
        parameters_schema: json!({
            "type": "object",
            "properties": {
                "message": { "type": "string" }
            },
            "required": ["message"]
        }),
        permission_level: crate::openhuman::tools::PermissionLevel::Write,
        category: crate::openhuman::tools::ToolCategory::Skill,
        scope: crate::openhuman::tools::ToolScope::All,
        adapter_id: "test-adapter".into(),
        provenance,
    }
}

fn sample_provenance(
    provider_id: &str,
    capability_id: Option<&str>,
    risk_level: ToolRiskLevel,
) -> ToolProvenance {
    ToolProvenance {
        provider_id: ProviderId::new(provider_id).unwrap(),
        capability_id: capability_id.map(|s| s.to_string()),
        source_digest: None,
        risk_level,
        policy_surface: PolicySurface::None,
    }
}

// ---------------------------------------------------------------------------
// ToolPattern matching
// ---------------------------------------------------------------------------

#[test]
fn test_pattern_all_from_provider_matches() {
    let pid = ProviderId::new("test").unwrap();
    let provenance = sample_provenance("test", None, ToolRiskLevel::Low);
    let pattern = ToolPattern::AllFromProvider(pid);
    assert!(pattern.matches(&provenance));
}

#[test]
fn test_pattern_all_from_provider_does_not_match_different_provider() {
    let pid = ProviderId::new("other").unwrap();
    let provenance = sample_provenance("test", None, ToolRiskLevel::Low);
    let pattern = ToolPattern::AllFromProvider(pid);
    assert!(!pattern.matches(&provenance));
}

#[test]
fn test_pattern_specific_tool_matches() {
    let provenance = sample_provenance("test", Some("send-message"), ToolRiskLevel::Low);
    let pattern = ToolPattern::SpecificTool {
        provider_id: ProviderId::new("test").unwrap(),
        capability_id: "send-message".into(),
    };
    assert!(pattern.matches(&provenance));
}

#[test]
fn test_pattern_specific_tool_does_not_match_different_capability() {
    let provenance = sample_provenance("test", Some("send-message"), ToolRiskLevel::Low);
    let pattern = ToolPattern::SpecificTool {
        provider_id: ProviderId::new("test").unwrap(),
        capability_id: "delete-all".into(),
    };
    assert!(!pattern.matches(&provenance));
}

#[test]
fn test_pattern_specific_tool_requires_capability_id() {
    let provenance = sample_provenance("test", None, ToolRiskLevel::Low);
    let pattern = ToolPattern::SpecificTool {
        provider_id: ProviderId::new("test").unwrap(),
        capability_id: "anything".into(),
    };
    assert!(!pattern.matches(&provenance));
}

#[test]
fn test_pattern_by_risk_level_matches_high_enough() {
    let provenance = sample_provenance("test", None, ToolRiskLevel::High);
    let pattern = ToolPattern::ByRiskLevel(ToolRiskLevel::Medium);
    assert!(pattern.matches(&provenance));
}

#[test]
fn test_pattern_by_risk_level_does_not_match_lower() {
    let provenance = sample_provenance("test", None, ToolRiskLevel::Low);
    let pattern = ToolPattern::ByRiskLevel(ToolRiskLevel::Medium);
    assert!(!pattern.matches(&provenance));
}

// ---------------------------------------------------------------------------
// Policy engine — enforcement disabled (default)
// ---------------------------------------------------------------------------

#[test]
fn test_permissive_engine_allows_all_tools() {
    let registry = trusted_registry();
    let engine = GeneratedToolPolicyEngine::permissive(registry);

    let definition = sample_definition(Some(sample_provenance(
        "trusted-provider",
        None,
        ToolRiskLevel::High,
    )));

    let decision = engine.evaluate(&definition);
    assert!(decision.is_allowed());
}

// ---------------------------------------------------------------------------
// Policy engine — allow rules
// ---------------------------------------------------------------------------

#[test]
fn test_allow_rule_allows_tool() {
    let registry = trusted_registry();
    let mut engine = GeneratedToolPolicyEngine::new(
        vec![],
        registry,
        true, // enforcement enabled
    );

    let pid = ProviderId::new("trusted-provider").unwrap();
    engine.add_rule(GeneratedToolPolicyRule::allow_provider(pid));

    let definition = sample_definition(Some(sample_provenance(
        "trusted-provider",
        None,
        ToolRiskLevel::Low,
    )));

    let decision = engine.evaluate(&definition);
    assert!(decision.is_allowed());
}

// ---------------------------------------------------------------------------
// Policy engine — deny rules
// ---------------------------------------------------------------------------

#[test]
fn test_deny_rule_denies_tool() {
    let registry = trusted_registry();
    let pid = ProviderId::new("trusted-provider").unwrap();
    let engine = GeneratedToolPolicyEngine::new(
        vec![GeneratedToolPolicyRule::deny_provider(
            pid,
            "Provider is temporarily blocked",
        )],
        registry,
        true,
    );

    let definition = sample_definition(Some(sample_provenance(
        "trusted-provider",
        None,
        ToolRiskLevel::Low,
    )));

    let decision = engine.evaluate(&definition);
    assert!(!decision.is_allowed());
    assert_eq!(
        decision.denial_reason(),
        Some("Provider is temporarily blocked")
    );
}

#[test]
fn test_deny_specific_capability() {
    let registry = trusted_registry();
    let pid = ProviderId::new("trusted-provider").unwrap();
    let engine = GeneratedToolPolicyEngine::new(
        vec![GeneratedToolPolicyRule::deny_capability(
            pid.clone(),
            "dangerous-action",
            "This action is not allowed",
        )],
        registry,
        true,
    );

    // This tool should be denied
    let dangerous = sample_definition(Some(sample_provenance(
        "trusted-provider",
        Some("dangerous-action"),
        ToolRiskLevel::High,
    )));
    assert!(!engine.evaluate(&dangerous).is_allowed());

    // This tool should be allowed (different capability)
    let safe = sample_definition(Some(sample_provenance(
        "trusted-provider",
        Some("safe-action"),
        ToolRiskLevel::Low,
    )));
    assert!(engine.evaluate(&safe).is_allowed());
}

// ---------------------------------------------------------------------------
// Provider revocation
// ---------------------------------------------------------------------------

#[test]
fn test_engine_denies_tools_from_revoked_provider() {
    // Create a registry with a disabled provider (revoked)
    let mut registry = CapabilityProviderRegistry::empty();
    let mut provider = CapabilityProvider::trusted("revoked-provider", "Revoked Provider").unwrap();
    provider.enabled_state = ProviderEnabledState::Disabled;
    registry.register(provider);

    let engine = GeneratedToolPolicyEngine::new(vec![], registry, true);

    let definition = sample_definition(Some(sample_provenance(
        "revoked-provider",
        None,
        ToolRiskLevel::Low,
    )));

    let decision = engine.evaluate(&definition);
    assert!(!decision.is_allowed());
    assert!(decision.denial_reason().unwrap().contains("not active"));
}

#[test]
fn test_engine_does_not_deny_tools_from_active_provider_without_rules() {
    let registry = trusted_registry();
    // No rules, enforcement on — tools from trusted providers with valid
    // provenance should be allowed by default.
    let engine = GeneratedToolPolicyEngine::new(vec![], registry, true);

    let definition = sample_definition(Some(sample_provenance(
        "trusted-provider",
        None,
        ToolRiskLevel::Medium,
    )));

    let decision = engine.evaluate(&definition);
    assert!(decision.is_allowed());
}

// ---------------------------------------------------------------------------
// Priority ordering
// ---------------------------------------------------------------------------

#[test]
fn test_higher_priority_rule_wins() {
    let registry = trusted_registry();
    let pid = ProviderId::new("trusted-provider").unwrap();
    let engine = GeneratedToolPolicyEngine::new(
        vec![
            GeneratedToolPolicyRule {
                name: "low-priority-deny".into(),
                pattern: ToolPattern::AllFromProvider(pid.clone()),
                action: PolicyAction::Deny {
                    reason: "Low priority deny".into(),
                },
                priority: 0,
            },
            GeneratedToolPolicyRule {
                name: "high-priority-allow".into(),
                pattern: ToolPattern::AllFromProvider(pid.clone()),
                action: PolicyAction::Allow,
                priority: 100,
            },
        ],
        registry,
        true,
    );

    let definition = sample_definition(Some(sample_provenance(
        "trusted-provider",
        None,
        ToolRiskLevel::Medium,
    )));

    let decision = engine.evaluate(&definition);
    // High-priority allow wins
    assert!(decision.is_allowed());
}

// ---------------------------------------------------------------------------
// Tools without provenance
// ---------------------------------------------------------------------------

#[test]
fn test_tool_without_provenance_is_allowed_when_enforcement_on() {
    let registry = trusted_registry();
    let engine = GeneratedToolPolicyEngine::new(
        vec![],
        registry,
        true, // enforcement on
    );

    let definition = sample_definition(None);
    let decision = engine.evaluate(&definition);
    assert!(
        decision.is_allowed(),
        "tools without provenance should be allowed"
    );
}

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

#[test]
fn test_audit_event_creation() {
    let event = ToolExecutionAuditEvent::new("my-tool");
    assert_eq!(event.tool_name, "my-tool");
    assert!(event.provider_id.is_none());
    assert!(event.capability_id.is_none());
    assert!(event.risk_level.is_none());
    assert!(event.policy_decision.is_allowed());
    assert!(event.approval_id.is_none());
    assert!(event.execution_outcome.is_none());
    // Timestamp should be a valid RFC 3339 string
    chrono::DateTime::parse_from_rfc3339(&event.timestamp).expect("valid timestamp");
}

#[test]
fn test_audit_event_with_provenance() {
    let provenance = sample_provenance("trusted-provider", Some("my-cap"), ToolRiskLevel::High);
    let event = ToolExecutionAuditEvent::new("my-tool").with_provenance(Some(&provenance));

    assert_eq!(event.provider_id.as_deref(), Some("trusted-provider"));
    assert_eq!(event.capability_id.as_deref(), Some("my-cap"));
    assert_eq!(event.risk_level, Some(ToolRiskLevel::High));
}

#[test]
fn test_audit_event_with_decision() {
    let decision = PolicyDecision::Denied {
        rule_name: "test-rule".into(),
        reason: "Not allowed".into(),
    };
    let event = ToolExecutionAuditEvent::new("my-tool").with_decision(decision.clone());

    assert_eq!(event.policy_decision, decision);
}

#[test]
fn test_audit_event_with_approval_and_outcome() {
    let mut event = ToolExecutionAuditEvent::new("my-tool");
    event.execution_outcome = Some(ExecutionOutcome::Success);
    event.approval_id = Some("approval-123".into());

    assert_eq!(event.execution_outcome, Some(ExecutionOutcome::Success));
    assert_eq!(event.approval_id.as_deref(), Some("approval-123"));
}

// ---------------------------------------------------------------------------
// evaluate_with_audit
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_with_audit_returns_decision_and_event() {
    let registry = trusted_registry();
    let pid = ProviderId::new("trusted-provider").unwrap();
    let engine = GeneratedToolPolicyEngine::new(
        vec![GeneratedToolPolicyRule::deny_provider(
            pid,
            "Blocked for maintenance",
        )],
        registry,
        true,
    );

    let definition = sample_definition(Some(sample_provenance(
        "trusted-provider",
        None,
        ToolRiskLevel::Low,
    )));

    let (decision, event) = engine.evaluate_with_audit(&definition);

    assert!(!decision.is_allowed());
    assert_eq!(event.tool_name, "send_update");
    assert_eq!(event.provider_id.as_deref(), Some("trusted-provider"));
    assert_eq!(event.policy_decision, decision);
}

// ---------------------------------------------------------------------------
// record_execution
// ---------------------------------------------------------------------------

#[test]
fn test_record_execution() {
    let registry = trusted_registry();
    let mut engine = GeneratedToolPolicyEngine::permissive(registry);

    let definition = sample_definition(Some(sample_provenance(
        "trusted-provider",
        None,
        ToolRiskLevel::Low,
    )));

    let (_, mut event) = engine.evaluate_with_audit(&definition);

    engine.record_execution(
        &mut event,
        ExecutionOutcome::Success,
        Some("approval-42".into()),
    );

    assert_eq!(event.execution_outcome, Some(ExecutionOutcome::Success));
    assert_eq!(event.approval_id.as_deref(), Some("approval-42"));
}

// ---------------------------------------------------------------------------
// Policy rule factory methods
// ---------------------------------------------------------------------------

#[test]
fn test_deny_provider_rule_creation() {
    let pid = ProviderId::new("bad-actor").unwrap();
    let rule = GeneratedToolPolicyRule::deny_provider(pid, "Security concern");
    assert!(rule.name.contains("bad-actor"));
    assert!(matches!(rule.pattern, ToolPattern::AllFromProvider(_)));
    assert!(rule.action.is_denied());
    assert_eq!(rule.action.denial_reason(), Some("Security concern"));
}

#[test]
fn test_deny_capability_rule_creation() {
    let pid = ProviderId::new("test").unwrap();
    let rule = GeneratedToolPolicyRule::deny_capability(pid, "delete-all", "Too dangerous");
    assert!(rule.name.contains("delete-all"));
    assert!(matches!(rule.pattern, ToolPattern::SpecificTool { .. }));
}

#[test]
fn test_allow_provider_rule_creation() {
    let pid = ProviderId::new("good-actor").unwrap();
    let rule = GeneratedToolPolicyRule::allow_provider(pid);
    assert!(rule.action.is_allowed());
}
