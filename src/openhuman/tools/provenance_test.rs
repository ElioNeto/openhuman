use serde_json::json;

use super::*;
use crate::openhuman::capability_provider::CapabilityProvider;
use crate::openhuman::tools::generated::GeneratedToolDefinition;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
        permission_level: PermissionLevel::Write,
        category: super::super::ToolCategory::Skill,
        scope: super::super::ToolScope::All,
        adapter_id: "test-adapter".into(),
        provenance,
    }
}

fn trusted_registry() -> CapabilityProviderRegistry {
    let mut registry = CapabilityProviderRegistry::empty();
    registry.register(CapabilityProvider::trusted("trusted-provider", "Trusted Provider").unwrap());
    registry.register(CapabilityProvider::trusted("another-provider", "Another Provider").unwrap());
    registry
}

fn untrusted_provider_registry() -> CapabilityProviderRegistry {
    let mut registry = CapabilityProviderRegistry::empty();
    registry.register(CapabilityProvider::untrusted("untrusted-provider").unwrap());
    registry
}

fn disabled_provider_registry() -> CapabilityProviderRegistry {
    let mut registry = CapabilityProviderRegistry::empty();
    let mut provider =
        CapabilityProvider::trusted("disabled-provider", "Disabled Provider").unwrap();
    provider.enabled_state = ProviderEnabledState::Disabled;
    registry.register(provider);
    registry
}

// ---------------------------------------------------------------------------
// Tool risk level
// ---------------------------------------------------------------------------

#[test]
fn test_risk_level_from_permission() {
    assert_eq!(
        ToolRiskLevel::from_permission(PermissionLevel::None),
        ToolRiskLevel::Low
    );
    assert_eq!(
        ToolRiskLevel::from_permission(PermissionLevel::ReadOnly),
        ToolRiskLevel::Low
    );
    assert_eq!(
        ToolRiskLevel::from_permission(PermissionLevel::Write),
        ToolRiskLevel::Medium
    );
    assert_eq!(
        ToolRiskLevel::from_permission(PermissionLevel::Execute),
        ToolRiskLevel::High
    );
    assert_eq!(
        ToolRiskLevel::from_permission(PermissionLevel::Dangerous),
        ToolRiskLevel::Critical
    );
}

// ---------------------------------------------------------------------------
// Admission gate — basic
// ---------------------------------------------------------------------------

#[test]
fn test_admission_passes_valid_tool_with_provenance() {
    let registry = trusted_registry();
    let gate = AdmissionGate::strict(registry);

    let provenance = ToolProvenance {
        provider_id: ProviderId::new("trusted-provider").unwrap(),
        capability_id: Some("send-message".into()),
        source_digest: Some("sha256:abc123".into()),
        risk_level: ToolRiskLevel::Medium,
        policy_surface: PolicySurface::None,
    };
    let definition = sample_definition(Some(provenance));

    let outcome = gate.admit(&definition);
    assert!(
        outcome.is_admitted(),
        "expected admitted, got: {:?}",
        outcome.reason()
    );
}

#[test]
fn test_admission_passes_tool_without_provenance_when_permissive() {
    let registry = CapabilityProviderRegistry::empty();
    let gate = AdmissionGate::permissive(registry);
    let definition = sample_definition(None);

    let outcome = gate.admit(&definition);
    assert!(outcome.is_admitted());
}

#[test]
fn test_admission_rejects_tool_without_provenance_when_strict() {
    let registry = CapabilityProviderRegistry::empty();
    let gate = AdmissionGate::strict(registry);
    let definition = sample_definition(None);

    let outcome = gate.admit(&definition);
    assert!(!outcome.is_admitted());
    assert!(outcome.reason().unwrap().contains("missing provenance"));
}

// ---------------------------------------------------------------------------
// Provider checks
// ---------------------------------------------------------------------------

#[test]
fn test_admission_rejects_unknown_provider() {
    let registry = CapabilityProviderRegistry::empty();
    let gate = AdmissionGate::strict(registry);

    let provenance = ToolProvenance {
        provider_id: ProviderId::new("unknown-provider").unwrap(),
        capability_id: None,
        source_digest: None,
        risk_level: ToolRiskLevel::Low,
        policy_surface: PolicySurface::None,
    };
    let definition = sample_definition(Some(provenance));

    let outcome = gate.admit(&definition);
    assert!(!outcome.is_admitted());
    assert!(outcome.reason().unwrap().contains("not registered"));
}

#[test]
fn test_admission_rejects_untrusted_provider() {
    let registry = untrusted_provider_registry();
    let gate = AdmissionGate::strict(registry);

    let provenance = ToolProvenance {
        provider_id: ProviderId::new("untrusted-provider").unwrap(),
        capability_id: None,
        source_digest: None,
        risk_level: ToolRiskLevel::Low,
        policy_surface: PolicySurface::None,
    };
    let definition = sample_definition(Some(provenance));

    let outcome = gate.admit(&definition);
    assert!(!outcome.is_admitted());
    assert!(outcome.reason().unwrap().contains("not active"));
}

#[test]
fn test_admission_rejects_disabled_provider() {
    let registry = disabled_provider_registry();
    let gate = AdmissionGate::strict(registry);

    let provenance = ToolProvenance {
        provider_id: ProviderId::new("disabled-provider").unwrap(),
        capability_id: None,
        source_digest: None,
        risk_level: ToolRiskLevel::Low,
        policy_surface: PolicySurface::None,
    };
    let definition = sample_definition(Some(provenance));

    let outcome = gate.admit(&definition);
    assert!(!outcome.is_admitted());
    assert!(outcome.reason().unwrap().contains("not active"));
}

// ---------------------------------------------------------------------------
// Tool name validation
// ---------------------------------------------------------------------------

#[test]
fn test_admission_rejects_empty_name() {
    let gate = AdmissionGate::permissive(CapabilityProviderRegistry::empty());
    let mut definition = sample_definition(None);
    definition.name = "".into();

    let outcome = gate.admit(&definition);
    assert!(!outcome.is_admitted());
    assert!(outcome.reason().unwrap().contains("non-empty"));
}

#[test]
fn test_admission_rejects_invalid_tool_name() {
    let gate = AdmissionGate::permissive(CapabilityProviderRegistry::empty());

    for bad_name in &[
        "SendUpdate",  // uppercase
        "send-update", // hyphen
        "send update", // space
        "123tool",     // starts with digit
        "_tool",       // starts with underscore
    ] {
        let mut definition = sample_definition(None);
        definition.name = bad_name.to_string();
        let outcome = gate.admit(&definition);
        assert!(
            !outcome.is_admitted(),
            "expected '{}' to be rejected",
            bad_name
        );
    }
}

#[test]
fn test_admission_accepts_valid_tool_name() {
    let gate = AdmissionGate::permissive(CapabilityProviderRegistry::empty());

    for good_name in &["tool", "send_update", "get_data_v2", "a"] {
        let mut definition = sample_definition(None);
        definition.name = good_name.to_string();
        let outcome = gate.admit(&definition);
        assert!(
            outcome.is_admitted(),
            "expected '{}' to be admitted, got: {:?}",
            good_name,
            outcome.reason()
        );
    }
}

// ---------------------------------------------------------------------------
// Risk-level checks
// ---------------------------------------------------------------------------

#[test]
fn test_admission_rejects_low_risk_with_write_permission() {
    let registry = trusted_registry();
    let gate = AdmissionGate::strict(registry);

    let provenance = ToolProvenance {
        provider_id: ProviderId::new("trusted-provider").unwrap(),
        capability_id: None,
        source_digest: None,
        risk_level: ToolRiskLevel::Low,
        policy_surface: PolicySurface::None,
    };
    let mut definition = sample_definition(Some(provenance));
    definition.permission_level = PermissionLevel::Write;

    let outcome = gate.admit(&definition);
    assert!(!outcome.is_admitted());
    assert!(outcome.reason().unwrap().contains("risk level"));
}

#[test]
fn test_admission_passes_medium_risk_with_write_permission() {
    let registry = trusted_registry();
    let gate = AdmissionGate::strict(registry);

    let provenance = ToolProvenance {
        provider_id: ProviderId::new("trusted-provider").unwrap(),
        capability_id: None,
        source_digest: None,
        risk_level: ToolRiskLevel::Medium,
        policy_surface: PolicySurface::None,
    };
    let mut definition = sample_definition(Some(provenance));
    definition.permission_level = PermissionLevel::Write;

    let outcome = gate.admit(&definition);
    assert!(outcome.is_admitted());
}

#[test]
fn test_admission_passes_low_risk_with_read_permission() {
    let registry = trusted_registry();
    let gate = AdmissionGate::strict(registry);

    let provenance = ToolProvenance {
        provider_id: ProviderId::new("trusted-provider").unwrap(),
        capability_id: None,
        source_digest: None,
        risk_level: ToolRiskLevel::Low,
        policy_surface: PolicySurface::None,
    };
    let mut definition = sample_definition(Some(provenance));
    definition.permission_level = PermissionLevel::ReadOnly;

    let outcome = gate.admit(&definition);
    assert!(outcome.is_admitted());
}

// ---------------------------------------------------------------------------
// Batch admission
// ---------------------------------------------------------------------------

#[test]
fn test_admit_all_returns_diagnostics_and_admitted_list() {
    let registry = trusted_registry();
    let gate = AdmissionGate::strict(registry);

    let admissible = sample_definition(Some(ToolProvenance {
        provider_id: ProviderId::new("trusted-provider").unwrap(),
        capability_id: None,
        source_digest: None,
        risk_level: ToolRiskLevel::Medium,
        policy_surface: PolicySurface::None,
    }));

    let rejectable = {
        let mut def = sample_definition(Some(ToolProvenance {
            provider_id: ProviderId::new("trusted-provider").unwrap(),
            capability_id: None,
            source_digest: None,
            risk_level: ToolRiskLevel::Low,
            policy_surface: PolicySurface::None,
        }));
        def.name = "rejected_tool".into();
        def.permission_level = PermissionLevel::Write;
        def
    };

    let definitions = vec![admissible, rejectable];
    let (diagnostics, admitted) = gate.admit_all(&definitions);

    assert_eq!(diagnostics.len(), 2);
    assert_eq!(admitted.len(), 1);

    assert!(diagnostics[0].admitted);
    assert!(!diagnostics[1].admitted);
    assert_eq!(admitted[0].name, "send_update");
}

// ---------------------------------------------------------------------------
// Enforcement off: backward compatibility
// ---------------------------------------------------------------------------

#[test]
fn test_permissive_gate_passes_all_tools_without_provenance() {
    let registry = CapabilityProviderRegistry::empty();
    let gate = AdmissionGate::permissive(registry);

    let def1 = sample_definition(None);
    let mut def2 = sample_definition(None);
    def2.name = "another_tool".into();

    let (diagnostics, admitted) = gate.admit_all(&[def1, def2]);
    assert_eq!(diagnostics.len(), 2);
    assert!(diagnostics.iter().all(|d| d.admitted));
    assert_eq!(admitted.len(), 2);
}

// ---------------------------------------------------------------------------
// ToolProvenance serialization
// ---------------------------------------------------------------------------

#[test]
fn test_provenance_serde_roundtrip() {
    let provenance = ToolProvenance {
        provider_id: ProviderId::new("test-provider").unwrap(),
        capability_id: Some("my-capability".into()),
        source_digest: Some("sha256:def456".into()),
        risk_level: ToolRiskLevel::High,
        policy_surface: PolicySurface::Network,
    };

    let json = serde_json::to_string_pretty(&provenance).unwrap();
    let deserialized: ToolProvenance = serde_json::from_str(&json).unwrap();

    assert_eq!(provenance.provider_id, deserialized.provider_id);
    assert_eq!(provenance.capability_id, deserialized.capability_id);
    assert_eq!(provenance.source_digest, deserialized.source_digest);
    assert_eq!(provenance.risk_level, deserialized.risk_level);
    assert_eq!(provenance.policy_surface, deserialized.policy_surface);
}

// ---------------------------------------------------------------------------
// Validate tool name
// ---------------------------------------------------------------------------

#[test]
fn test_validate_tool_name_edge_cases() {
    assert!(validate_tool_name("a").is_ok());
    assert!(validate_tool_name("z_1").is_ok());

    assert!(validate_tool_name("").is_err());
    assert!(validate_tool_name(" ").is_err());
    assert!(validate_tool_name(&"a".repeat(129)).is_err());
}
