use super::*;
use crate::openhuman::capability_provider::types::{
    CapabilityProvider, ProviderEnabledState, ProviderTrustState,
};

#[test]
fn test_empty_registry() {
    let registry = CapabilityProviderRegistry::empty();
    assert!(registry.is_empty());
    assert_eq!(registry.len(), 0);
    assert!(registry.list().is_empty());
}

#[test]
fn test_default_registry_is_empty() {
    let registry = CapabilityProviderRegistry::default();
    assert!(registry.is_empty());
}

#[test]
fn test_register_and_lookup() {
    let mut registry = CapabilityProviderRegistry::empty();
    let provider = CapabilityProvider::trusted("composio", "Composio Integrations").unwrap();
    registry.register(provider);

    assert_eq!(registry.len(), 1);
    assert!(!registry.is_empty());

    let id = ProviderId::new("composio").unwrap();
    let found = registry.get(&id);
    assert!(found.is_some());
    assert_eq!(found.unwrap().display_name, "Composio Integrations");
}

#[test]
fn test_lookup_by_str() {
    let mut registry = CapabilityProviderRegistry::empty();
    let provider = CapabilityProvider::trusted("smithery", "Smithery.ai Registry").unwrap();
    registry.register(provider);

    let found = registry.get_by_str("smithery");
    assert!(found.is_some());
    assert_eq!(found.unwrap().display_name, "Smithery.ai Registry");
}

#[test]
fn test_lookup_by_invalid_str_returns_none() {
    let registry = CapabilityProviderRegistry::empty();
    assert!(registry.get_by_str("").is_none());
    assert!(registry.get_by_str("white space").is_none());
}

#[test]
fn test_is_active() {
    let mut registry = CapabilityProviderRegistry::empty();
    let provider = CapabilityProvider::trusted("active-provider", "Active").unwrap();
    let id = ProviderId::new("active-provider").unwrap();
    registry.register(provider);

    assert!(registry.is_active(&id));
    assert!(registry.is_active_by_str("active-provider"));
}

#[test]
fn test_is_active_returns_false_for_unknown() {
    let registry = CapabilityProviderRegistry::empty();
    let id = ProviderId::new("unknown").unwrap();
    assert!(!registry.is_active(&id));
    assert!(!registry.is_active_by_str("unknown"));
}

#[test]
fn test_disabled_provider_not_active() {
    let mut registry = CapabilityProviderRegistry::empty();
    let mut provider = CapabilityProvider::trusted("disabled-provider", "Disabled").unwrap();
    provider.enabled_state = ProviderEnabledState::Disabled;
    let id = ProviderId::new("disabled-provider").unwrap();
    registry.register(provider);

    assert!(!registry.is_active(&id));
}

#[test]
fn test_untrusted_provider_not_active() {
    let mut registry = CapabilityProviderRegistry::empty();
    let mut provider = CapabilityProvider::trusted("untrusted", "Untrusted").unwrap();
    provider.trust_state = ProviderTrustState::Untrusted;
    let id = ProviderId::new("untrusted").unwrap();
    registry.register(provider);

    assert!(!registry.is_active(&id));
}

#[test]
fn test_from_providers() {
    let providers = vec![
        CapabilityProvider::trusted("a", "Provider A").unwrap(),
        CapabilityProvider::trusted("b", "Provider B").unwrap(),
    ];
    let registry = CapabilityProviderRegistry::from_providers(providers);
    assert_eq!(registry.len(), 2);
}

#[test]
fn test_list_is_sorted() {
    let providers = vec![
        CapabilityProvider::trusted("z-provider", "Z").unwrap(),
        CapabilityProvider::trusted("a-provider", "A").unwrap(),
        CapabilityProvider::trusted("m-provider", "M").unwrap(),
    ];
    let registry = CapabilityProviderRegistry::from_providers(providers);
    let list = registry.list();
    assert_eq!(list.len(), 3);
    assert_eq!(list[0].id.as_str(), "a-provider");
    assert_eq!(list[1].id.as_str(), "m-provider");
    assert_eq!(list[2].id.as_str(), "z-provider");
}

#[test]
fn test_list_by_trust() {
    let mut registry = CapabilityProviderRegistry::empty();
    registry.register(CapabilityProvider::trusted("trusted-1", "Trusted One").unwrap());
    registry.register(CapabilityProvider::trusted("trusted-2", "Trusted Two").unwrap());
    registry.register(CapabilityProvider::untrusted("untrusted-1").unwrap());
    registry.register(CapabilityProvider::untrusted("untrusted-2").unwrap());

    let trusted = registry.list_by_trust(true);
    assert_eq!(trusted.len(), 2);
    assert!(trusted.iter().all(|p| p.trust_state.is_trusted()));

    let untrusted = registry.list_by_trust(false);
    assert_eq!(untrusted.len(), 2);
    assert!(untrusted.iter().all(|p| !p.trust_state.is_trusted()));
}

#[test]
fn test_list_active() {
    let mut registry = CapabilityProviderRegistry::empty();
    registry.register(CapabilityProvider::trusted("active-1", "Active One").unwrap());
    let mut disabled = CapabilityProvider::trusted("disabled", "Disabled").unwrap();
    disabled.enabled_state = ProviderEnabledState::Disabled;
    registry.register(disabled);
    registry.register(CapabilityProvider::untrusted("untrusted").unwrap());

    let active = registry.list_active();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id.as_str(), "active-1");
}

#[test]
fn test_remove_provider() {
    let mut registry = CapabilityProviderRegistry::empty();
    let id = ProviderId::new("removable").unwrap();
    registry.register(CapabilityProvider::trusted("removable", "To Remove").unwrap());
    assert_eq!(registry.len(), 1);

    let removed = registry.remove(&id);
    assert!(removed.is_some());
    assert!(registry.is_empty());
}

#[test]
fn test_remove_unknown_returns_none() {
    let mut registry = CapabilityProviderRegistry::empty();
    let id = ProviderId::new("nonexistent").unwrap();
    assert!(registry.remove(&id).is_none());
}

#[test]
fn test_duplicate_id_replaces() {
    let mut registry = CapabilityProviderRegistry::empty();
    registry.register(CapabilityProvider::trusted("dup", "Original").unwrap());
    registry.register(CapabilityProvider::trusted("dup", "Replacement").unwrap());
    assert_eq!(registry.len(), 1);
    let id = ProviderId::new("dup").unwrap();
    assert_eq!(registry.get(&id).unwrap().display_name, "Replacement");
}

#[test]
fn test_get_unknown_returns_none() {
    let registry = CapabilityProviderRegistry::empty();
    let id = ProviderId::new("not-found").unwrap();
    assert!(registry.get(&id).is_none());
}
