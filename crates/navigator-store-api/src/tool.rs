use navigator_domain::{Revision, ToolDefinition, ToolFailure, ToolInvocation, ToolResult};
use serde::{Deserialize, Serialize};
use std::{future::Future, time::Duration};

use navigator_domain::{
    ConsumerKey, FencingEpoch, SemanticDigest, SessionId, Timestamp, ToolCancellationId,
    ToolConnectionId, ToolDispatchId, ToolInvocationId, ToolProviderId, ToolRegistrationId,
};

use crate::{CanonicalInput, MutableRequest, Mutation, RequestContext, StoreAction, StoreError};

pub const MAX_TOOL_REGISTRATIONS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ToolRegistrationSnapshot {
    pub registration_id: ToolRegistrationId,
    pub session_id: SessionId,
    pub consumer_key: ConsumerKey,
    pub definition: ToolDefinition,
    pub revision: Revision,
    pub registered_at: Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterTool {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub owner_epoch: FencingEpoch,
    pub consumer_key: ConsumerKey,
    pub registration_id: ToolRegistrationId,
    pub definition: ToolDefinition,
}

impl MutableRequest for RegisterTool {
    fn context(&self) -> RequestContext {
        self.context
    }
    fn action(&self) -> StoreAction {
        StoreAction::RegisterTool
    }
    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        input.identity(*self.session_id.as_uuid().as_bytes());
        input.identity(*self.registration_id.as_uuid().as_bytes());
        input.u64(self.owner_epoch.get());
        input.bytes(self.consumer_key.as_str().as_bytes());
        input.bytes(
            &serde_json::to_vec(&self.definition).expect("validated Tool definition serializes"),
        );
        input.finish(self.action())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReserveToolInvocation {
    pub context: RequestContext,
    pub owner_epoch: FencingEpoch,
    pub invocation: ToolInvocation,
    pub dispatch_id: ToolDispatchId,
    pub provider_id: ToolProviderId,
    pub registration_id: ToolRegistrationId,
    pub deadline: Timestamp,
    pub lease_duration: Duration,
}

impl MutableRequest for ReserveToolInvocation {
    fn context(&self) -> RequestContext {
        self.context
    }
    fn action(&self) -> StoreAction {
        StoreAction::ReserveToolInvocation
    }
    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        input.bytes(
            &serde_json::to_vec(&self.invocation).expect("validated Tool invocation serializes"),
        );
        input.identity(*self.dispatch_id.as_uuid().as_bytes());
        input.identity(*self.provider_id.as_uuid().as_bytes());
        input.identity(*self.registration_id.as_uuid().as_bytes());
        input.fixed(&self.deadline.unix_seconds().to_be_bytes());
        input.u64(u64::from(self.deadline.nanoseconds()));
        input.u64(self.owner_epoch.get());
        input.u64(u64::try_from(self.lease_duration.as_millis()).unwrap_or(u64::MAX));
        input.finish(self.action())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolTransition {
    Start,
    Complete(ToolResult),
    Fail(ToolFailure),
    MarkUncertain,
    RequestCancel { cancellation_id: ToolCancellationId },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ToolDispatchSnapshot {
    pub dispatch_id: ToolDispatchId,
    pub provider_id: ToolProviderId,
    pub server_sequence: u64,
    pub deadline: Timestamp,
    pub connection_id: Option<ToolConnectionId>,
    pub connection_generation: Option<u64>,
    pub cancellation_id: Option<ToolCancellationId>,
    pub cancellation_server_sequence: Option<u64>,
    pub terminal_digest: Option<SemanticDigest>,
}

impl ToolDispatchSnapshot {
    #[must_use]
    pub fn structurally_valid(&self) -> bool {
        self.server_sequence > 0
            && self.connection_generation != Some(0)
            && (self.connection_id.is_some() == self.connection_generation.is_some())
            && (self.cancellation_id.is_some() == self.cancellation_server_sequence.is_some())
            && self
                .cancellation_server_sequence
                .is_none_or(|v| v > self.server_sequence)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionToolInvocation {
    pub context: RequestContext,
    pub invocation_id: ToolInvocationId,
    pub owner_epoch: FencingEpoch,
    pub expected_revision: Revision,
    pub transition: ToolTransition,
    pub provider_id: ToolProviderId,
    pub connection_id: ToolConnectionId,
    pub connection_generation: u64,
    pub dispatch_id: ToolDispatchId,
    pub server_sequence: u64,
}

impl MutableRequest for TransitionToolInvocation {
    fn context(&self) -> RequestContext {
        self.context
    }
    fn action(&self) -> StoreAction {
        StoreAction::TransitionToolInvocation
    }
    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        input.identity(*self.invocation_id.as_uuid().as_bytes());
        input.u64(self.owner_epoch.get());
        input.u64(self.expected_revision.get());
        input.bytes(
            &serde_json::to_vec(&self.transition).expect("validated Tool transition serializes"),
        );
        input.identity(*self.provider_id.as_uuid().as_bytes());
        input.identity(*self.connection_id.as_uuid().as_bytes());
        input.u64(self.connection_generation);
        input.identity(*self.dispatch_id.as_uuid().as_bytes());
        input.u64(self.server_sequence);
        input.finish(self.action())
    }
}

pub trait ToolStore: Send + Sync {
    /// Exact durable binding used to reconcile an Approval effect after a
    /// process crash, including terminal Tool invocations.
    fn load_tool_invocation_by_approval_effect(
        &self,
        _effect_id: navigator_domain::RequestId,
    ) -> impl Future<Output = Result<Option<ToolInvocationSnapshot>, StoreError>> + Send {
        async { Err(StoreError::Unavailable) }
    }
    fn connect_tool_provider(
        &self,
        command: ConnectToolProvider,
    ) -> impl Future<Output = Result<ToolProviderConnectionSnapshot, StoreError>> + Send;
    fn register_tool(
        &self,
        command: RegisterTool,
    ) -> impl Future<Output = Result<Mutation<ToolRegistrationSnapshot>, StoreError>> + Send;
    fn reserve_tool_invocation(
        &self,
        command: ReserveToolInvocation,
    ) -> impl Future<Output = Result<ToolInvocationSnapshot, StoreError>> + Send;
    fn transition_tool_invocation(
        &self,
        command: TransitionToolInvocation,
    ) -> impl Future<Output = Result<ToolInvocationSnapshot, StoreError>> + Send;
    fn load_tool_invocation(
        &self,
        invocation_id: ToolInvocationId,
    ) -> impl Future<Output = Result<Option<ToolInvocationSnapshot>, StoreError>> + Send;
    fn list_recoverable_tool_invocations(
        &self,
        session_id: SessionId,
    ) -> impl Future<Output = Result<Vec<ToolInvocationSnapshot>, StoreError>> + Send;
    fn load_tool_registration(
        &self,
        session_id: SessionId,
        registration_id: ToolRegistrationId,
    ) -> impl Future<Output = Result<Option<ToolRegistrationSnapshot>, StoreError>> + Send;
    fn list_tool_registrations(
        &self,
        session_id: SessionId,
    ) -> impl Future<Output = Result<Vec<ToolRegistrationSnapshot>, StoreError>> + Send;
    fn list_provider_replay(
        &self,
        session_id: SessionId,
        provider_id: ToolProviderId,
        after_server_sequence: u64,
    ) -> impl Future<Output = Result<Vec<ToolInvocationSnapshot>, StoreError>> + Send;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ToolProviderConnectionSnapshot {
    pub session_id: SessionId,
    pub consumer_key: ConsumerKey,
    pub provider_id: ToolProviderId,
    pub connection_id: ToolConnectionId,
    pub registration_ids: Vec<ToolRegistrationId>,
    pub generation: u64,
    pub acknowledged_server_sequence: u64,
    pub next_server_sequence: u64,
    pub connected_at: Timestamp,
}
impl ToolProviderConnectionSnapshot {
    #[must_use]
    pub fn is_structurally_valid(&self) -> bool {
        let mut ids = self.registration_ids.clone();
        ids.sort();
        ids.dedup();
        self.generation > 0
            && self.next_server_sequence > self.acknowledged_server_sequence
            && !self.registration_ids.is_empty()
            && self.registration_ids.len() <= MAX_TOOL_REGISTRATIONS
            && self.registration_ids == ids
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectToolProvider {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub owner_epoch: FencingEpoch,
    pub consumer_key: ConsumerKey,
    pub provider_id: ToolProviderId,
    pub connection_id: ToolConnectionId,
    pub after_server_sequence: u64,
    pub registration_ids: Vec<ToolRegistrationId>,
}
impl MutableRequest for ConnectToolProvider {
    fn context(&self) -> RequestContext {
        self.context
    }
    fn action(&self) -> StoreAction {
        StoreAction::ConnectToolProvider
    }
    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        input.identity(*self.session_id.as_uuid().as_bytes());
        input.u64(self.owner_epoch.get());
        input.bytes(self.consumer_key.as_str().as_bytes());
        input.identity(*self.provider_id.as_uuid().as_bytes());
        input.identity(*self.connection_id.as_uuid().as_bytes());
        input.u64(self.after_server_sequence);
        let mut ids = self.registration_ids.clone();
        ids.sort();
        for id in ids {
            input.identity(*id.as_uuid().as_bytes());
        }
        input.finish(self.action())
    }
}

/// Durable Tool work is reserved before a Consumer handler can observe it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolInvocationPhase {
    Reserved,
    Started,
    Uncertain,
    Completed,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ToolTerminal {
    Completed(ToolResult),
    Failed(ToolFailure),
}

/// Infrastructure-neutral persisted projection. Custom deserialization keeps
/// phase/terminal correlation and invocation identity fail-closed on reopen.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    try_from = "ToolInvocationSnapshotWire",
    into = "ToolInvocationSnapshotWire"
)]
pub struct ToolInvocationSnapshot {
    registration_id: ToolRegistrationId,
    definition: ToolDefinition,
    invocation: ToolInvocation,
    phase: ToolInvocationPhase,
    terminal: Option<ToolTerminal>,
    revision: Revision,
    dispatch: ToolDispatchSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ToolInvocationSnapshotWire {
    registration_id: ToolRegistrationId,
    definition: ToolDefinition,
    invocation: ToolInvocation,
    phase: ToolInvocationPhase,
    terminal: Option<ToolTerminal>,
    revision: Revision,
    dispatch: ToolDispatchSnapshot,
}

impl ToolInvocationSnapshot {
    pub fn new(
        registration_id: ToolRegistrationId,
        definition: ToolDefinition,
        invocation: ToolInvocation,
        phase: ToolInvocationPhase,
        terminal: Option<ToolTerminal>,
        revision: Revision,
        dispatch: ToolDispatchSnapshot,
    ) -> Result<Self, ToolSnapshotError> {
        if !dispatch.structurally_valid() {
            return Err(ToolSnapshotError::InvalidDispatch);
        }
        let terminal_id = terminal.as_ref().map(|terminal| match terminal {
            ToolTerminal::Completed(result) => result.invocation_id(),
            ToolTerminal::Failed(failure) => failure.invocation_id,
        });
        if terminal_id.is_some_and(|id| id != invocation.invocation_id()) {
            return Err(ToolSnapshotError::IdentityMismatch);
        }
        if let Some(ToolTerminal::Completed(result)) = terminal.as_ref()
            && result.artifacts().iter().any(|artifact| {
                artifact.session_id() != invocation.session_id()
                    || artifact.creator_participant_id() != invocation.participant_id()
                    || artifact.creator_operation_id() != invocation.operation_id()
            })
        {
            return Err(ToolSnapshotError::ArtifactCreatorMismatch);
        }
        let terminal_matches_phase = matches!(
            (&phase, &terminal),
            (
                ToolInvocationPhase::Reserved
                    | ToolInvocationPhase::Started
                    | ToolInvocationPhase::Uncertain,
                None
            ) | (
                ToolInvocationPhase::Completed,
                Some(ToolTerminal::Completed(_))
            ) | (ToolInvocationPhase::Failed, Some(ToolTerminal::Failed(_)))
        );
        if !terminal_matches_phase {
            return Err(ToolSnapshotError::PhaseTerminalMismatch);
        }
        if definition.name() != invocation.tool_name()
            || definition.version() != invocation.tool_version()
        {
            return Err(ToolSnapshotError::DefinitionMismatch);
        }
        Ok(Self {
            registration_id,
            definition,
            invocation,
            phase,
            terminal,
            revision,
            dispatch,
        })
    }

    #[must_use]
    pub const fn registration_id(&self) -> ToolRegistrationId {
        self.registration_id
    }

    #[must_use]
    pub const fn definition(&self) -> &ToolDefinition {
        &self.definition
    }
    #[must_use]
    pub const fn invocation(&self) -> &ToolInvocation {
        &self.invocation
    }
    #[must_use]
    pub const fn phase(&self) -> ToolInvocationPhase {
        self.phase
    }
    #[must_use]
    pub const fn terminal(&self) -> Option<&ToolTerminal> {
        self.terminal.as_ref()
    }
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
    #[must_use]
    pub const fn dispatch(&self) -> &ToolDispatchSnapshot {
        &self.dispatch
    }
}

impl TryFrom<ToolInvocationSnapshotWire> for ToolInvocationSnapshot {
    type Error = ToolSnapshotError;
    fn try_from(value: ToolInvocationSnapshotWire) -> Result<Self, Self::Error> {
        Self::new(
            value.registration_id,
            value.definition,
            value.invocation,
            value.phase,
            value.terminal,
            value.revision,
            value.dispatch,
        )
    }
}

impl From<ToolInvocationSnapshot> for ToolInvocationSnapshotWire {
    fn from(value: ToolInvocationSnapshot) -> Self {
        Self {
            registration_id: value.registration_id,
            definition: value.definition,
            invocation: value.invocation,
            phase: value.phase,
            terminal: value.terminal,
            revision: value.revision,
            dispatch: value.dispatch,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ToolSnapshotError {
    #[error("Tool terminal belongs to a different invocation")]
    IdentityMismatch,
    #[error("Tool phase and terminal payload disagree")]
    PhaseTerminalMismatch,
    #[error("Tool definition identity differs from the reserved invocation")]
    DefinitionMismatch,
    #[error("Tool result Artifact was not created by its invocation")]
    ArtifactCreatorMismatch,
    #[error("Tool dispatch metadata is structurally invalid")]
    InvalidDispatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use navigator_domain::{
        BoundedText, CanonicalJson, Capability, EffectClass, IdempotencyContract,
        MAX_TOOL_INLINE_BYTES, MAX_TOOL_SCHEMA_BYTES, OperationId, ParticipantId, RequestId,
        SessionId, ToolCancellation, ToolInvocationId, ToolName, ToolTimeout, ToolVersion,
    };
    use uuid::Uuid;

    fn definition() -> ToolDefinition {
        ToolDefinition::new(
            ToolName::new("records.lookup").unwrap(),
            ToolVersion::new("v1").unwrap(),
            CanonicalJson::<MAX_TOOL_SCHEMA_BYTES>::new(r#"{"type":"object"}"#).unwrap(),
            CanonicalJson::<MAX_TOOL_SCHEMA_BYTES>::new(r#"{"type":"object"}"#).unwrap(),
            Capability::new("tool.records.lookup").unwrap(),
            ToolTimeout::from_millis(1_000).unwrap(),
            ToolCancellation::Cooperative,
            EffectClass::ReadOnly,
            IdempotencyContract::NoExternalEffect,
        )
        .unwrap()
    }

    fn invocation(id: u128) -> ToolInvocation {
        ToolInvocation::new(
            ToolInvocationId::from_uuid(Uuid::from_u128(id)).unwrap(),
            RequestId::from_uuid(Uuid::from_u128(2)).unwrap(),
            SessionId::from_uuid(Uuid::from_u128(3)).unwrap(),
            ParticipantId::from_uuid(Uuid::from_u128(4)).unwrap(),
            OperationId::from_uuid(Uuid::from_u128(5)).unwrap(),
            ToolName::new("records.lookup").unwrap(),
            ToolVersion::new("v1").unwrap(),
            CanonicalJson::<MAX_TOOL_INLINE_BYTES>::new("{}").unwrap(),
        )
        .unwrap()
    }

    fn dispatch() -> ToolDispatchSnapshot {
        ToolDispatchSnapshot {
            dispatch_id: navigator_domain::ToolDispatchId::from_uuid(Uuid::from_u128(10)).unwrap(),
            provider_id: navigator_domain::ToolProviderId::from_uuid(Uuid::from_u128(11)).unwrap(),
            server_sequence: 1,
            deadline: Timestamp::new(100, 0).unwrap(),
            connection_id: Some(ToolConnectionId::from_uuid(Uuid::from_u128(13)).unwrap()),
            connection_generation: Some(1),
            cancellation_id: None,
            cancellation_server_sequence: None,
            terminal_digest: None,
        }
    }

    fn registration_id() -> ToolRegistrationId {
        ToolRegistrationId::from_uuid(Uuid::from_u128(12)).unwrap()
    }

    #[test]
    fn nonterminal_and_terminal_phase_mutants_are_rejected_on_reopen() {
        let reserved = ToolInvocationSnapshot::new(
            registration_id(),
            definition(),
            invocation(1),
            ToolInvocationPhase::Reserved,
            None,
            Revision::initial(),
            dispatch(),
        )
        .unwrap();
        assert_eq!(reserved.registration_id(), registration_id());
        let mut wire = serde_json::to_value(reserved).unwrap();
        wire["phase"] = serde_json::json!("completed");
        assert!(serde_json::from_value::<ToolInvocationSnapshot>(wire).is_err());

        let failed = ToolFailure {
            invocation_id: invocation(1).invocation_id(),
            kind: navigator_domain::ToolFailureKind::HandlerFailed,
            message: BoundedText::new("handler failed").unwrap(),
            retryable: false,
        };
        assert_eq!(
            ToolInvocationSnapshot::new(
                registration_id(),
                definition(),
                invocation(1),
                ToolInvocationPhase::Completed,
                Some(ToolTerminal::Failed(failed)),
                Revision::initial(),
                dispatch()
            ),
            Err(ToolSnapshotError::PhaseTerminalMismatch)
        );
    }

    #[test]
    fn terminal_identity_and_definition_identity_are_bound() {
        let failed = ToolFailure {
            invocation_id: invocation(9).invocation_id(),
            kind: navigator_domain::ToolFailureKind::HandlerFailed,
            message: BoundedText::new("handler failed").unwrap(),
            retryable: false,
        };
        assert_eq!(
            ToolInvocationSnapshot::new(
                registration_id(),
                definition(),
                invocation(1),
                ToolInvocationPhase::Failed,
                Some(ToolTerminal::Failed(failed)),
                Revision::initial(),
                dispatch()
            ),
            Err(ToolSnapshotError::IdentityMismatch)
        );

        let mut wire = serde_json::to_value(definition()).unwrap();
        wire["name"] = serde_json::json!("other.tool");
        let other: ToolDefinition = serde_json::from_value(wire).unwrap();
        assert_eq!(
            ToolInvocationSnapshot::new(
                registration_id(),
                other,
                invocation(1),
                ToolInvocationPhase::Reserved,
                None,
                Revision::initial(),
                dispatch()
            ),
            Err(ToolSnapshotError::DefinitionMismatch)
        );
    }
}
