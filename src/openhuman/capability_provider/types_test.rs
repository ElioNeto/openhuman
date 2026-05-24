use super::*;

#[test]
fn test_valid_provider_id() {
    let id = ProviderId::new("composio").unwrap();
    assert_eq!(id.as_str(), "composio");

    let id = ProviderId::new("smithery-ai").unwrap();
    assert_eq!(id.as_str(), "smithery-ai");

    let id = ProviderId::new("my_provider").unwrap();
    assert_eq!(id.as_str(), "my_provider");

    // IDs are trimmed
    let id = ProviderId::new("  my-provider  ").unwrap();
    assert_eq!(id.as_str(), "my-provider");
}

#[test]
fn test_empty_provider_id_rejected() {
    let err = ProviderId::new("").unwrap_err();
    assert!(err.0.contains("empty"));

    let err = ProviderId::new("   ").unwrap_err();
    assert!(err.0.contains("empty"));
}

#[test]
fn test_too_long_provider_id_rejected() {
    let long = "a".repeat(65);
    let err = ProviderId::new(long).unwrap_err();
    assert!(err.0.contains("max length"));
}

#[test]
fn test_invalid_chars_provider_id_rejected() {
    let err = ProviderId::new("hello world").unwrap_err();
    assert!(err.0.contains("ASCII alphanumeric"));

    let err = ProviderId::new("provider@name").unwrap_err();
    assert!(err.0.contains("ASCII alphanumeric"));

    let err = ProviderId::new("provider.name").unwrap_err();
    assert!(err.0.contains("ASCII alphanumeric"));
}

#[test]
fn test_provider_id_display_and_conversion() {
    let id = ProviderId::new("my-provider").unwrap();
    assert_eq!(format!("{id}"), "my-provider");

    let s: String = id.clone().into();
    assert_eq!(s, "my-provider");

    let id2 = ProviderId::try_from("my-provider".to_string()).unwrap();
    assert_eq!(id, id2);
}

#[test]
fn test_provider_id_serialize_roundtrip() {
    let id = ProviderId::new("test-provider").unwrap();
    let json = serde_json::to_string(&id).unwrap();
    assert_eq!(json, "\"test-provider\"");
    let deserialized: ProviderId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, deserialized);
}

#[test]
fn test_provider_trust_state() {
    assert!(ProviderTrustState::Trusted.is_trusted());
    assert!(!ProviderTrustState::Untrusted.is_trusted());
}

#[test]
fn test_provider_enabled_state() {
    assert!(ProviderEnabledState::Enabled.is_enabled());
    assert!(!ProviderEnabledState::Disabled.is_enabled());
}

#[test]
fn test_capability_provider_trusted() {
    let provider = CapabilityProvider::trusted("composio", "Composio Integrations").unwrap();
    assert_eq!(provider.id.as_str(), "composio");
    assert_eq!(provider.display_name, "Composio Integrations");
    assert!(provider.trust_state.is_trusted());
    assert!(provider.enabled_state.is_enabled());
    assert!(provider.is_active());
    assert!(provider.source_uri.is_none());
    assert!(provider.source_digest.is_none());
}

#[test]
fn test_capability_provider_untrusted() {
    let provider = CapabilityProvider::untrusted("unknown-source").unwrap();
    assert_eq!(provider.id.as_str(), "unknown-source");
    assert!(!provider.trust_state.is_trusted());
    assert!(provider.enabled_state.is_enabled());
    assert!(!provider.is_active());
}

#[test]
fn test_capability_provider_not_active_when_disabled() {
    let mut provider = CapabilityProvider::trusted("test", "Test").unwrap();
    provider.enabled_state = ProviderEnabledState::Disabled;
    assert!(!provider.is_active());

    provider.enabled_state = ProviderEnabledState::Enabled;
    provider.trust_state = ProviderTrustState::Untrusted;
    assert!(!provider.is_active());
}

#[test]
fn test_capability_provider_serde_roundtrip() {
    let provider = CapabilityProvider {
        id: ProviderId::new("test-provider").unwrap(),
        display_name: "Test Provider".into(),
        source_uri: Some("https://example.com/provider.json".into()),
        source_digest: Some("abc123".into()),
        trust_state: ProviderTrustState::Trusted,
        enabled_state: ProviderEnabledState::Enabled,
    };
    let json = serde_json::to_string_pretty(&provider).unwrap();
    let deserialized: CapabilityProvider = serde_json::from_str(&json).unwrap();
    assert_eq!(provider.id, deserialized.id);
    assert_eq!(provider.display_name, deserialized.display_name);
    assert_eq!(provider.source_uri, deserialized.source_uri);
    assert_eq!(provider.source_digest, deserialized.source_digest);
    assert_eq!(provider.trust_state, deserialized.trust_state);
    assert_eq!(provider.enabled_state, deserialized.enabled_state);
}

#[test]
fn test_provider_id_error_display() {
    let err = ProviderIdError("too short".into());
    assert_eq!(format!("{err}"), "invalid provider id: too short");
}
