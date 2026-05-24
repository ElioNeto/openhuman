//! Trusted external capability provider registry.
//!
//! This domain provides a generic registry for trusted external capability
//! providers that can register generated tools at runtime. It defines
//! provider metadata types, a validated identifier, and a config-backed
//! registry with lookup and list helpers for policy and diagnostics callers.
//!
//! ## Architecture
//!
//! - [`types::ProviderId`] — validated unique identifier (ASCII alphanumeric + hyphens/underscores).
//! - [`types::ProviderTrustState`] — trust classification (trusted or untrusted).
//! - [`types::ProviderEnabledState`] — operational state (enabled or disabled).
//! - [`types::CapabilityProvider`] — full provider metadata struct.
//! - [`registry::CapabilityProviderRegistry`] — config-backed registry with lookup/list helpers.
//!
//! ## Future use
//!
//! Issue #2542 (provenance) wires `provider_id` into `GeneratedToolDefinition`.
//! Issue #2543 (policy) consults `CapabilityProviderRegistry` for runtime
//! admission, revocation, and audit.

mod registry;
mod types;

pub use registry::CapabilityProviderRegistry;
pub use types::{CapabilityProvider, ProviderEnabledState, ProviderId, ProviderTrustState};
