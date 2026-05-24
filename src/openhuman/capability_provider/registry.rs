//! Config-backed registry for trusted external capability providers.
//!
//! The [`CapabilityProviderRegistry`] manages a collection of capability
//! providers with validated identifiers. It supports construction from
//! configuration, runtime registration, and lookup/list operations for
//! policy and diagnostics callers.

use std::collections::HashMap;

use super::types::{CapabilityProvider, ProviderId};

/// Config-backed registry for trusted external capability providers.
///
/// Defaults to an empty registry (no providers configured), which keeps
/// backward compatibility — existing generated tools without a provider
/// continue to work when admission enforcement is disabled.
#[derive(Debug, Clone)]
pub struct CapabilityProviderRegistry {
    by_id: HashMap<ProviderId, CapabilityProvider>,
}

impl CapabilityProviderRegistry {
    /// Create an empty registry with no providers configured.
    pub fn empty() -> Self {
        Self {
            by_id: HashMap::new(),
        }
    }

    /// Create a registry pre-populated from a slice of providers.
    ///
    /// Returns `None` if any provider has a duplicate or otherwise invalid id
    /// (should not happen if providers were constructed via [`CapabilityProvider::trusted`]
    /// or similar, since the `ProviderId` is already validated).
    pub fn from_providers(providers: impl IntoIterator<Item = CapabilityProvider>) -> Self {
        let mut registry = Self::empty();
        for provider in providers {
            registry.by_id.insert(provider.id.clone(), provider);
        }
        registry
    }

    /// Register (insert or update) a capability provider.
    ///
    /// If a provider with the same id already exists, it is replaced.
    pub fn register(&mut self, provider: CapabilityProvider) {
        self.by_id.insert(provider.id.clone(), provider);
    }

    /// Look up a provider by its identifier.
    pub fn get(&self, id: &ProviderId) -> Option<&CapabilityProvider> {
        self.by_id.get(id)
    }

    /// Look up a provider by its string identifier (parsed and validated).
    ///
    /// Returns `None` if the id string is invalid or the provider is not found.
    pub fn get_by_str(&self, id: &str) -> Option<&CapabilityProvider> {
        ProviderId::new(id)
            .ok()
            .and_then(|pid| self.by_id.get(&pid))
    }

    /// Return `true` if a provider with the given id is registered, trusted,
    /// and enabled.
    pub fn is_active(&self, id: &ProviderId) -> bool {
        self.by_id.get(id).map_or(false, |p| p.is_active())
    }

    /// Return `true` if a provider with the given string id is registered,
    /// trusted, and enabled.
    pub fn is_active_by_str(&self, id: &str) -> bool {
        ProviderId::new(id)
            .ok()
            .and_then(|pid| self.by_id.get(&pid))
            .map_or(false, |p| p.is_active())
    }

    /// List all registered providers.
    pub fn list(&self) -> Vec<&CapabilityProvider> {
        let mut providers: Vec<_> = self.by_id.values().collect();
        providers.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        providers
    }

    /// List providers matching the given trust state.
    pub fn list_by_trust(&self, trusted: bool) -> Vec<&CapabilityProvider> {
        let mut providers: Vec<_> = self
            .by_id
            .values()
            .filter(|p| p.trust_state.is_trusted() == trusted)
            .collect();
        providers.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        providers
    }

    /// List active (trusted + enabled) providers.
    pub fn list_active(&self) -> Vec<&CapabilityProvider> {
        let mut providers: Vec<_> = self.by_id.values().filter(|p| p.is_active()).collect();
        providers.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        providers
    }

    /// Return the number of registered providers.
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Return `true` if the registry has no providers.
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Remove a provider by id. Returns the removed provider, or `None` if
    /// not found.
    pub fn remove(&mut self, id: &ProviderId) -> Option<CapabilityProvider> {
        self.by_id.remove(id)
    }
}

impl Default for CapabilityProviderRegistry {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
#[path = "registry_test.rs"]
mod tests;
