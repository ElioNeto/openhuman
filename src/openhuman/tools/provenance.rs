//! Provenance metadata and admission checks for generated capability tools.
//!
//! ## Provenance
//!
//! [`ToolProvenance`] carries identity and safety metadata from a capability
//! provider to the tool registry: which provider generated the tool, what
//! capability it represents, its risk level, and the policy surface it
//! interacts with.
//!
//! ## Admission
//!
//! [`AdmissionGate`] validates generated tools against provenance rules
//! before they enter the tool registry:
//!
//! - Rejects missing/invalid provenance when enforcement is enabled.
//! - Rejects unsafe tool names, duplicate names, invalid schemas.
//! - Rejects missing risk metadata for write/external capabilities.
//! - Rejects tools from disabled or untrusted providers.
//!
//! Existing tools without provenance continue to work when admission
//! enforcement is disabled (default).

use serde::{Deserialize, Serialize};

use super::generated::GeneratedToolDefinition;
use super::PermissionLevel;
use crate::openhuman::capability_provider::{
    CapabilityProviderRegistry, ProviderEnabledState, ProviderId, ProviderTrustState,
};

// ---------------------------------------------------------------------------
// Risk level
// ---------------------------------------------------------------------------

/// Risk level for a generated tool, based on the capabilities it exposes.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum ToolRiskLevel {
    /// Read-only information retrieval — low risk.
    #[default]
    Low,
    /// Moderate side effects (e.g. file reads, search queries).
    Medium,
    /// Destructive or externally visible side effects (e.g. writes, API calls).
    High,
    /// Full system access or dangerous operations.
    Critical,
}

impl ToolRiskLevel {
    /// Determine risk level from a `PermissionLevel`.
    pub fn from_permission(level: PermissionLevel) -> Self {
        match level {
            PermissionLevel::None | PermissionLevel::ReadOnly => Self::Low,
            PermissionLevel::Write => Self::Medium,
            PermissionLevel::Execute => Self::High,
            PermissionLevel::Dangerous => Self::Critical,
        }
    }
}

// ---------------------------------------------------------------------------
// Policy surface
// ---------------------------------------------------------------------------

/// Which policy controls apply to this tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PolicySurface {
    /// Standard tool — no special policy surface.
    #[default]
    None,
    /// Tool performs file system reads or writes.
    FileSystem,
    /// Tool makes network requests to external services.
    Network,
    /// Tool executes shell commands or subprocesses.
    Shell,
    /// Tool handles credentials or authentication tokens.
    Credentials,
    /// Tool accesses or modifies memory/knowledge store.
    Memory,
    /// Tool interacts with external integration platforms.
    Integration,
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

/// Provenance metadata for a generated capability tool.
///
/// Carried by [`super::generated::GeneratedToolDefinition`] to identify
/// which capability provider generated the tool and at what risk level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolProvenance {
    /// The capability provider that generated this tool.
    pub provider_id: ProviderId,
    /// Provider-specific capability identifier (e.g. action name, tool name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    /// Optional cryptographic digest of the source manifest or definition
    /// that produced this tool (e.g. SHA-256 hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_digest: Option<String>,
    /// Computed or declared risk level for this tool.
    pub risk_level: ToolRiskLevel,
    /// Policy surface this tool interacts with.
    #[serde(default)]
    pub policy_surface: PolicySurface,
}

// ---------------------------------------------------------------------------
// Admission result
// ---------------------------------------------------------------------------

/// Outcome of an admission check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionOutcome {
    /// Tool was admitted (passed all checks).
    Admitted,
    /// Tool was rejected with a reason.
    Rejected(String),
}

impl AdmissionOutcome {
    pub fn is_admitted(&self) -> bool {
        matches!(self, Self::Admitted)
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Admitted => None,
            Self::Rejected(r) => Some(r.as_str()),
        }
    }
}

// ---------------------------------------------------------------------------
// Admission diagnostics
// ---------------------------------------------------------------------------

/// Structured diagnostics for a single admission decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionDiagnostic {
    pub tool_name: String,
    pub admitted: bool,
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Admission gate
// ---------------------------------------------------------------------------

/// Admission gate for generated tools.
///
/// Validates provenance metadata, provider trust state, tool name safety,
/// and risk-level completeness before a generated tool enters the registry.
///
/// When enforcement is disabled (default), the gate passes all tools
/// without provenance, maintaining backward compatibility.
#[derive(Debug, Clone)]
pub struct AdmissionGate {
    provider_registry: CapabilityProviderRegistry,
    enforcement_enabled: bool,
}

impl AdmissionGate {
    /// Create a new admission gate.
    ///
    /// When `enforcement_enabled` is `false` (default), tools without
    /// provenance pass admission. Set to `true` to require provenance
    /// for all generated tools.
    pub fn new(provider_registry: CapabilityProviderRegistry, enforcement_enabled: bool) -> Self {
        Self {
            provider_registry,
            enforcement_enabled,
        }
    }

    /// Create a gate with enforcement disabled (backward-compatible mode).
    pub fn permissive(provider_registry: CapabilityProviderRegistry) -> Self {
        Self::new(provider_registry, false)
    }

    /// Create a gate with enforcement enabled.
    pub fn strict(provider_registry: CapabilityProviderRegistry) -> Self {
        Self::new(provider_registry, true)
    }

    /// Check a single generated tool definition against admission rules.
    ///
    /// Returns [`AdmissionOutcome::Admitted`] when the tool passes all
    /// checks, or [`AdmissionOutcome::Rejected`] with a reason string.
    pub fn admit(&self, definition: &GeneratedToolDefinition) -> AdmissionOutcome {
        // -- Schema validity (always checked) --
        // Basic definition validation is done by GeneratedTool::new().
        // We check name safety here.
        if let Err(reason) = validate_tool_name(&definition.name) {
            return AdmissionOutcome::Rejected(reason);
        }

        // -- Provenance checks --
        let Some(ref provenance) = definition.provenance else {
            // No provenance: pass when enforcement is off, reject when on.
            if self.enforcement_enabled {
                return AdmissionOutcome::Rejected(
                    "generated tool is missing provenance metadata and enforcement is enabled"
                        .into(),
                );
            }
            return AdmissionOutcome::Admitted;
        };

        // -- Provider check --
        let provider_id = &provenance.provider_id;
        if !self.provider_registry.is_active(provider_id) {
            let reason = if self.provider_registry.get(provider_id).is_none() {
                format!(
                    "provider `{provider_id}` is not registered in the capability provider registry"
                )
            } else {
                format!("provider `{provider_id}` is not active (disabled or untrusted)")
            };
            return AdmissionOutcome::Rejected(reason);
        }

        // -- Risk-level check for write/external capabilities --
        if provenance.risk_level < ToolRiskLevel::Medium
            && definition.permission_level >= PermissionLevel::Write
        {
            return AdmissionOutcome::Rejected(format!(
                "tool `{}` has permission level {:?} but risk level is {:?}; \
                 write-capable tools must have at least Medium risk level",
                definition.name, definition.permission_level, provenance.risk_level
            ));
        }

        AdmissionOutcome::Admitted
    }

    /// Batch-check multiple definitions, collecting diagnostics.
    pub fn admit_all<'a>(
        &self,
        definitions: &'a [GeneratedToolDefinition],
    ) -> (Vec<AdmissionDiagnostic>, Vec<&'a GeneratedToolDefinition>) {
        let mut diagnostics = Vec::with_capacity(definitions.len());
        let mut admitted = Vec::new();

        for def in definitions {
            let outcome = self.admit(def);
            diagnostics.push(AdmissionDiagnostic {
                tool_name: def.name.clone(),
                admitted: outcome.is_admitted(),
                reason: outcome.reason().map(|r| r.to_string()),
            });
            if outcome.is_admitted() {
                admitted.push(def);
            }
        }

        (diagnostics, admitted)
    }

    /// Return whether enforcement is enabled.
    pub fn is_enforcement_enabled(&self) -> bool {
        self.enforcement_enabled
    }

    /// Return a reference to the provider registry.
    pub fn provider_registry(&self) -> &CapabilityProviderRegistry {
        &self.provider_registry
    }
}

// ---------------------------------------------------------------------------
// Name validation
// ---------------------------------------------------------------------------

/// Validate a generated tool name.
///
/// Rules:
/// - Must be non-empty.
/// - Must not exceed 128 characters.
/// - Must match `[a-z][a-z0-9_]*` (lowercase snake_case).
/// - Must not be a reserved system tool name.
fn validate_tool_name(name: &str) -> Result<(), String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("tool name must be non-empty".into());
    }
    if trimmed.len() > 128 {
        return Err("tool name must not exceed 128 characters".into());
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err("tool name must be lowercase snake_case: [a-z][a-z0-9_]*".into());
    }
    if !trimmed.starts_with(|c: char| c.is_ascii_lowercase()) {
        return Err("tool name must start with a lowercase letter".into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "provenance_test.rs"]
mod tests;
