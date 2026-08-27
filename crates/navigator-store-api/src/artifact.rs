use std::future::Future;

use navigator_domain::{
    ArtifactDigest, ArtifactId, ArtifactMediaType, ArtifactSnapshot, FencingEpoch, HostId,
    OperationId, ParticipantId, RequestId, SessionId, Timestamp,
};

use crate::{CanonicalInput, Mutation, RequestContext, SemanticDigest, StoreAction, StoreError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishArtifact {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub owner: HostId,
    pub epoch: FencingEpoch,
    pub artifact_id: ArtifactId,
    pub creator_participant_id: ParticipantId,
    pub creator_operation_id: OperationId,
    pub media_type: ArtifactMediaType,
    pub size: u64,
    pub digest: ArtifactDigest,
    pub locator: String,
    pub retention_until: Timestamp,
    pub artifact_reservation_id: RequestId,
    /// Present exactly when `size > 0`; zero-byte artifacts do not manufacture an
    /// invalid zero-amount capacity reservation.
    pub byte_reservation_id: Option<RequestId>,
}

impl crate::MutableRequest for PublishArtifact {
    fn context(&self) -> RequestContext {
        self.context
    }

    fn action(&self) -> StoreAction {
        StoreAction::PublishArtifact
    }

    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        input.identity(*self.session_id.as_uuid().as_bytes());
        input.identity(*self.artifact_id.as_uuid().as_bytes());
        input.identity(*self.creator_participant_id.as_uuid().as_bytes());
        input.identity(*self.creator_operation_id.as_uuid().as_bytes());
        input.identity(*self.owner.as_uuid().as_bytes());
        input.u64(self.epoch.get());
        input.bytes(self.media_type.as_str().as_bytes());
        input.u64(self.size);
        input.fixed(&self.digest.as_bytes());
        input.bytes(self.locator.as_bytes());
        input.fixed(&self.retention_until.unix_seconds().to_be_bytes());
        input.u64(u64::from(self.retention_until.nanoseconds()));
        input.identity(*self.artifact_reservation_id.as_uuid().as_bytes());
        input.u64(u64::from(self.byte_reservation_id.is_some()));
        if let Some(reservation_id) = self.byte_reservation_id {
            input.identity(*reservation_id.as_uuid().as_bytes());
        }
        input.finish(self.action())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteArtifact {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub owner: HostId,
    pub epoch: FencingEpoch,
    pub artifact_id: ArtifactId,
}

impl crate::MutableRequest for DeleteArtifact {
    fn context(&self) -> RequestContext {
        self.context
    }

    fn action(&self) -> StoreAction {
        StoreAction::DeleteArtifact
    }

    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        input.identity(*self.session_id.as_uuid().as_bytes());
        input.identity(*self.artifact_id.as_uuid().as_bytes());
        input.identity(*self.owner.as_uuid().as_bytes());
        input.u64(self.epoch.get());
        input.finish(self.action())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EraseArtifact {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub owner: HostId,
    pub epoch: FencingEpoch,
    pub artifact_id: ArtifactId,
}

impl crate::MutableRequest for EraseArtifact {
    fn context(&self) -> RequestContext {
        self.context
    }
    fn action(&self) -> StoreAction {
        StoreAction::EraseArtifact
    }
    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        input.identity(*self.session_id.as_uuid().as_bytes());
        input.identity(*self.artifact_id.as_uuid().as_bytes());
        input.identity(*self.owner.as_uuid().as_bytes());
        input.u64(self.epoch.get());
        input.finish(self.action())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactAccess {
    pub session_id: SessionId,
    pub owner: HostId,
    pub epoch: FencingEpoch,
    pub artifact_id: ArtifactId,
}

pub trait ArtifactStore: Send + Sync {
    fn publish_artifact(
        &self,
        request: PublishArtifact,
    ) -> impl Future<Output = Result<Mutation<ArtifactSnapshot>, StoreError>> + Send;

    fn load_artifact(
        &self,
        access: ArtifactAccess,
    ) -> impl Future<Output = Result<ArtifactSnapshot, StoreError>> + Send;

    fn logically_delete_artifact(
        &self,
        request: DeleteArtifact,
    ) -> impl Future<Output = Result<Mutation<ArtifactSnapshot>, StoreError>> + Send;

    fn retention_eligible_artifacts(
        &self,
        now: Timestamp,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<ArtifactSnapshot>, StoreError>> + Send;

    /// Authenticates a pending filesystem erase before any external effect.
    ///
    /// Implementations must validate request-ledger identity here. An exact
    /// replay of an already recorded erasure returns its terminal snapshot;
    /// conflicting reuse must fail before the caller can remove a file.
    fn authorize_physical_erasure(
        &self,
        request: &EraseArtifact,
    ) -> impl Future<Output = Result<ArtifactSnapshot, StoreError>> + Send;

    fn record_physical_erasure(
        &self,
        request: EraseArtifact,
    ) -> impl Future<Output = Result<ArtifactSnapshot, StoreError>> + Send;
}
