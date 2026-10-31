//! A curated prelude for the common verify + evaluate + authorize flow.
//!
//! `use kya_sdk::prelude::*;` brings the types and functions a typical consumer
//! needs into scope in one line, without pulling in the whole facade surface.
//! It is intentionally small and stable: it covers configuring trust, building
//! a mandate and an intent, verifying a real signature, evaluating static
//! policy, inspecting structured results, and reaching the fail-closed
//! stage-D bridge.
//!
//! Everything here is a re-export of the crate's top-level items (which are in
//! turn re-exports of the reviewed inner crates); the prelude adds no behaviour.
//! The experimental AP2 adapter is deliberately **not** included — import it
//! explicitly from [`crate::ap2`] if you have read its limitations.

// Trust configuration and request conditions (facade-owned helpers).
pub use crate::{RequestConditions, TrustConfiguration, TrustConfigurationError};

// Explicit online-state helpers (eligibility is not authorization).
pub use crate::{online_state_is_unestablished, requires_online_authorization};

// Identity and explicit trust primitives.
pub use crate::{
    AgentId, IssuerId, MerchantId, PrincipalId, ResourceId, TrustAnchors, TrustedKeyRef,
    TrustedKeyStore,
};

// Evidence and the honest proof-of-possession state.
pub use crate::{DelegationClaim, ProofOfPossession, VerifiedDelegation, VerifiedMandate};

// Domain value types for building a mandate and an intent.
pub use crate::{
    Action, Audience, CurrencyCode, Mandate, Money, Scope, TransactionBinding, TransactionIntent,
    ValidityWindow,
};

// The real cryptographic verification entry points and their inputs.
pub use crate::{verify_delegation, verify_mandate, SignedClaim, SignedMandate};

// Static evaluation and structured results.
pub use crate::{evaluate, Decision, PolicyOutcome, ReasonCode};

// Stable error-code surface.
pub use crate::{AsErrorCode, ErrorCode};

// Stage-D fail-closed bridge and integration seams.
pub use crate::{
    authorize, AuthorityVerdict, AuthorizerError, IntegrationClient, OnlineAuthorizer,
};
