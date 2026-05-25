//! Types for external capability provider metadata and identity.
//!
//! This module defines the core types used by the capability provider
//! registry: provider identifiers, trust and enabled states, and the
//! full provider metadata struct.

use serde::{Deserialize, Serialize};

/// Maximum length for a `ProviderId` string.
const MAX_PROVIDER_ID_LEN: usize = 64;

/// Error returned when provider ID validation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIdError(pub String);

impl std::fmt::Display for ProviderIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid provider id: {}", self.0)
    }
}

impl std::error::Error for ProviderIdError {}

/// Validated unique identifier for a capability provider.
///
/// Must be non-empty, ASCII alphanumeric (plus hyphens and underscores),
/// and at most [`MAX_PROVIDER_ID_LEN`] characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProviderId(String);

impl ProviderId {
    /// Validate and construct a new `ProviderId`.
    ///
    /// Returns `ProviderIdError` if the input is empty, too long, or
    /// contains characters other than `[a-zA-Z0-9_-]`.
    pub fn new(id: impl Into<String>) -> Result<Self, ProviderIdError> {
        let id = id.into();
        let trimmed = id.trim().to_string();
        if trimmed.is_empty() {
            return Err(ProviderIdError("must not be empty".into()));
        }
        if trimmed.len() > MAX_PROVIDER_ID_LEN {
            return Err(ProviderIdError(format!(
                "max length is {MAX_PROVIDER_ID_LEN}, got {}",
                trimmed.len()
            )));
        }
        if !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(ProviderIdError(
                "must contain only ASCII alphanumeric characters, hyphens, or underscores".into(),
            ));
        }
        Ok(Self(trimmed))
    }

    /// Return the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProviderId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<ProviderId> for String {
    fn from(id: ProviderId) -> Self {
        id.0
    }
}

impl TryFrom<String> for ProviderId {
    type Error = ProviderIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        ProviderId::new(value)
    }
}

/// Trust classification for a capability provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProviderTrustState {
    /// Provider is trusted — generated tools from this provider may be
    /// automatically admitted when admission enforcement is enabled.
    #[default]
    Trusted,
    /// Provider is untrusted — generated tools require explicit approval
    /// or are denied, depending on policy configuration.
    Untrusted,
}

impl ProviderTrustState {
    pub fn is_trusted(&self) -> bool {
        matches!(self, Self::Trusted)
    }
}

/// Operational state for a capability provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProviderEnabledState {
    /// Provider is enabled — its tools may be registered and called.
    #[default]
    Enabled,
    /// Provider is disabled — its tools are not available for execution.
    Disabled,
}

impl ProviderEnabledState {
    pub fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled)
    }
}

/// Metadata describing a registered external capability provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityProvider {
    /// Unique provider identifier (e.g. `"smithery"`, `"composio"`).
    #[serde(flatten)]
    pub id: ProviderId,
    /// Human-readable display name (e.g. `"Smithery.ai MCP Registry"`).
    #[serde(default)]
    pub display_name: String,
    /// Optional origin URI (e.g. `"https://registry.smithery.ai"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_uri: Option<String>,
    /// Optional cryptographic digest of the provider's source metadata
    /// (e.g. SHA-256 hex of a registry endpoint's provider manifest).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_digest: Option<String>,
    /// Trust state — whether this provider is considered trusted.
    #[serde(default)]
    pub trust_state: ProviderTrustState,
    /// Enabled state — whether this provider's tools are available.
    #[serde(default)]
    pub enabled_state: ProviderEnabledState,
}

impl CapabilityProvider {
    /// Create a new trusted, enabled provider with the given id and
    /// display name.
    pub fn trusted(
        id: impl Into<String>,
        display_name: impl Into<String>,
    ) -> Result<Self, ProviderIdError> {
        Ok(Self {
            id: ProviderId::new(id)?,
            display_name: display_name.into(),
            source_uri: None,
            source_digest: None,
            trust_state: ProviderTrustState::Trusted,
            enabled_state: ProviderEnabledState::Enabled,
        })
    }

    /// Create a new untrusted, enabled provider.
    pub fn untrusted(id: impl Into<String>) -> Result<Self, ProviderIdError> {
        Ok(Self {
            id: ProviderId::new(id)?,
            display_name: String::new(),
            source_uri: None,
            source_digest: None,
            trust_state: ProviderTrustState::Untrusted,
            enabled_state: ProviderEnabledState::Enabled,
        })
    }

    /// Returns `true` if the provider is both trusted and enabled.
    pub fn is_active(&self) -> bool {
        self.trust_state.is_trusted() && self.enabled_state.is_enabled()
    }
}

#[cfg(test)]
#[path = "types_test.rs"]
mod tests;
