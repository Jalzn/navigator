use std::path::{Path, PathBuf};

use navigator_consumer_protocol::{CURRENT_MAJOR, CURRENT_MINOR, MAX_REQUEST_BYTES, v1};
use tonic::{
    Request, Status,
    metadata::MetadataValue,
    transport::{Channel, Endpoint},
};

use crate::{AUTHENTICATION_HEADER, BootstrapCredential, current_metadata};

pub struct SessionManifestSpecification {
    pub root_template: v1::RootTemplateSpecification,
    pub compatible_templates: Vec<v1::RootTemplateSpecification>,
    pub expected_compatibility: Option<[u8; 32]>,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("local connection failed")]
    Transport(#[from] tonic::transport::Error),
    #[error("local RPC failed")]
    Status(#[from] Status),
    #[error("bootstrap credential cannot be represented as gRPC metadata")]
    InvalidCredential,
}

pub struct LocalClient {
    inner: v1::navigator_consumer_client::NavigatorConsumerClient<Channel>,
    credential: MetadataValue<tonic::metadata::Ascii>,
    negotiation_id: Option<Vec<u8>>,
    configuration_identity: Option<Vec<u8>>,
}

impl LocalClient {
    /// Selects a negotiation token that was previously bound to the durable
    /// Consumer by an authenticated Session lifecycle request.
    pub fn select_bound_negotiation(&mut self, negotiation_id: uuid::Uuid) {
        self.negotiation_id = Some(negotiation_id.as_bytes().to_vec());
    }

    pub async fn connect(
        socket: impl AsRef<Path>,
        credential: &BootstrapCredential,
    ) -> Result<Self, ClientError> {
        let socket = PathBuf::from(socket.as_ref());
        let channel = Endpoint::from_shared(format!("unix:{}", socket.display()))?
            .connect()
            .await?;
        let text = std::str::from_utf8(credential.as_bytes())
            .map_err(|_| ClientError::InvalidCredential)?;
        let credential =
            MetadataValue::try_from(text).map_err(|_| ClientError::InvalidCredential)?;
        Ok(Self {
            inner: v1::navigator_consumer_client::NavigatorConsumerClient::new(channel)
                .max_decoding_message_size(MAX_REQUEST_BYTES)
                .max_encoding_message_size(MAX_REQUEST_BYTES),
            credential,
            negotiation_id: None,
            configuration_identity: None,
        })
    }

    pub async fn negotiate(&mut self) -> Result<v1::NegotiateResponse, ClientError> {
        let request = v1::NegotiateRequest {
            minimum_version: Some(v1::ProtocolVersion {
                major: CURRENT_MAJOR,
                minor: 0,
            }),
            maximum_version: Some(v1::ProtocolVersion {
                major: CURRENT_MAJOR,
                minor: CURRENT_MINOR,
            }),
            capabilities: vec![
                "events.replay.v1".to_owned(),
                "operation.execution.v1".to_owned(),
                "operation.cancellation.v1".to_owned(),
                "operational.projections.v1".to_owned(),
                "recovery.resolution.v1".to_owned(),
                "session.lifecycle.v1".to_owned(),
                "session.open-modes.v1".to_owned(),
            ],
        };
        let request = self.authenticated(request);
        let response = self.inner.negotiate(request).await?.into_inner();
        if let Some(v1::negotiate_response::Outcome::Negotiated(value)) = &response.outcome {
            self.negotiation_id = Some(value.negotiation_id.clone());
            self.configuration_identity = Some(value.configuration_identity.clone());
        }
        Ok(response)
    }

    pub async fn open(
        &mut self,
        request_id: uuid::Uuid,
        session_id: uuid::Uuid,
        consumer_key: String,
        root_template: v1::RootTemplateSpecification,
        expected_compatibility: Option<[u8; 32]>,
    ) -> Result<v1::OpenSessionResponse, ClientError> {
        let negotiation_id = self.negotiation_id().await?;
        let request = v1::OpenSessionRequest {
            metadata: Some(current_metadata(negotiation_id, &["session.lifecycle.v1"])),
            request_id: request_id.as_bytes().to_vec(),
            session_id: session_id.as_bytes().to_vec(),
            consumer_key,
            compatibility_identity: expected_compatibility
                .map_or_else(Vec::new, |value| value.to_vec()),
            root_template: Some(root_template),
            compatible_templates: Vec::new(),
            configuration_identity: Vec::new(),
            mode: v1::SessionOpenMode::Unspecified.into(),
        };
        let request = self.authenticated(request);
        Ok(self.inner.open_session(request).await?.into_inner())
    }

    pub async fn open_with_manifest(
        &mut self,
        request_id: uuid::Uuid,
        session_id: uuid::Uuid,
        consumer_key: String,
        manifest: SessionManifestSpecification,
    ) -> Result<v1::OpenSessionResponse, ClientError> {
        let negotiation_id = self.negotiation_id().await?;
        let request = v1::OpenSessionRequest {
            metadata: Some(current_metadata(negotiation_id, &["session.lifecycle.v1"])),
            request_id: request_id.as_bytes().to_vec(),
            session_id: session_id.as_bytes().to_vec(),
            consumer_key,
            compatibility_identity: manifest
                .expected_compatibility
                .map_or_else(Vec::new, |value| value.to_vec()),
            root_template: Some(manifest.root_template),
            compatible_templates: manifest.compatible_templates,
            configuration_identity: self.configuration_identity.clone().unwrap_or_default(),
            mode: v1::SessionOpenMode::Unspecified.into(),
        };
        let request = self.authenticated(request);
        Ok(self.inner.open_session(request).await?.into_inner())
    }

    pub async fn snapshot(
        &mut self,
        session_id: uuid::Uuid,
    ) -> Result<v1::SnapshotResponse, ClientError> {
        let negotiation_id = self.negotiation_id().await?;
        let request = v1::SnapshotRequest {
            metadata: Some(current_metadata(negotiation_id, &["session.lifecycle.v1"])),
            session_id: session_id.as_bytes().to_vec(),
        };
        let request = self.authenticated(request);
        Ok(self.inner.snapshot(request).await?.into_inner())
    }

    pub async fn read_projection(
        &mut self,
        session_id: uuid::Uuid,
        consumer_key: String,
        view: v1::ProjectionView,
        page_size: u32,
        page_token: String,
    ) -> Result<v1::ReadProjectionResponse, ClientError> {
        let negotiation_id = self.negotiation_id().await?;
        let request = v1::ReadProjectionRequest {
            metadata: Some(current_metadata(
                negotiation_id,
                &["operational.projections.v1"],
            )),
            session_id: session_id.as_bytes().to_vec(),
            view: view.into(),
            page_size,
            page_token,
            consumer_key,
        };
        let request = self.authenticated(request);
        Ok(self.inner.read_projection(request).await?.into_inner())
    }

    pub async fn close(
        &mut self,
        request_id: uuid::Uuid,
        session_id: uuid::Uuid,
    ) -> Result<v1::CloseSessionResponse, ClientError> {
        let negotiation_id = self.negotiation_id().await?;
        let request = v1::CloseSessionRequest {
            metadata: Some(current_metadata(negotiation_id, &["session.lifecycle.v1"])),
            request_id: request_id.as_bytes().to_vec(),
            session_id: session_id.as_bytes().to_vec(),
        };
        let request = self.authenticated(request);
        Ok(self.inner.close_session(request).await?.into_inner())
    }

    pub async fn start_operation(
        &mut self,
        request_id: uuid::Uuid,
        session_id: uuid::Uuid,
        participant_id: uuid::Uuid,
        input: Vec<u8>,
    ) -> Result<v1::StartOperationResponse, ClientError> {
        let negotiation_id = self.negotiation_id().await?;
        let request = v1::StartOperationRequest {
            metadata: Some(current_metadata(
                negotiation_id,
                &["operation.execution.v1"],
            )),
            request_id: request_id.as_bytes().to_vec(),
            session_id: session_id.as_bytes().to_vec(),
            participant_id: participant_id.as_bytes().to_vec(),
            input,
        };
        let request = self.authenticated(request);
        Ok(self.inner.start_operation(request).await?.into_inner())
    }

    pub async fn operation_snapshot(
        &mut self,
        session_id: uuid::Uuid,
        operation_id: uuid::Uuid,
    ) -> Result<v1::OperationSnapshotResponse, ClientError> {
        let negotiation_id = self.negotiation_id().await?;
        let request = v1::OperationSnapshotRequest {
            metadata: Some(current_metadata(
                negotiation_id,
                &["operation.execution.v1"],
            )),
            session_id: session_id.as_bytes().to_vec(),
            operation_id: operation_id.as_bytes().to_vec(),
        };
        let request = self.authenticated(request);
        Ok(self.inner.operation_snapshot(request).await?.into_inner())
    }

    pub async fn cancel_subtree(
        &mut self,
        request_id: uuid::Uuid,
        session_id: uuid::Uuid,
        root_participant_id: uuid::Uuid,
    ) -> Result<v1::CancelSubtreeResponse, ClientError> {
        let negotiation_id = self.negotiation_id().await?;
        let request = v1::CancelSubtreeRequest {
            metadata: Some(current_metadata(
                negotiation_id,
                &["operation.cancellation.v1"],
            )),
            request_id: request_id.as_bytes().to_vec(),
            session_id: session_id.as_bytes().to_vec(),
            root_participant_id: root_participant_id.as_bytes().to_vec(),
        };
        let request = self.authenticated(request);
        Ok(self.inner.cancel_subtree(request).await?.into_inner())
    }

    pub async fn resume_session(
        &mut self,
        request_id: uuid::Uuid,
        session_id: uuid::Uuid,
    ) -> Result<v1::ResumeSessionResponse, ClientError> {
        let negotiation_id = self.negotiation_id().await?;
        let request = v1::ResumeSessionRequest {
            metadata: Some(current_metadata(
                negotiation_id,
                &["recovery.resolution.v1"],
            )),
            request_id: request_id.as_bytes().to_vec(),
            session_id: session_id.as_bytes().to_vec(),
        };
        let request = self.authenticated(request);
        Ok(self.inner.resume_session(request).await?.into_inner())
    }

    pub async fn resolve_uncertainty(
        &mut self,
        request: v1::ResolveUncertaintyRequest,
    ) -> Result<v1::ResolveUncertaintyResponse, ClientError> {
        let negotiation_id = self.negotiation_id().await?;
        let mut request = request;
        request.metadata = Some(current_metadata(
            negotiation_id,
            &["recovery.resolution.v1"],
        ));
        let request = self.authenticated(request);
        Ok(self.inner.resolve_uncertainty(request).await?.into_inner())
    }

    pub async fn events(
        &mut self,
        session_id: uuid::Uuid,
        after_position: u64,
    ) -> Result<tonic::Streaming<v1::SubscribeEventsResponse>, ClientError> {
        let negotiation_id = self.negotiation_id().await?;
        let request = v1::SubscribeEventsRequest {
            metadata: Some(current_metadata(negotiation_id, &["events.replay.v1"])),
            session_id: session_id.as_bytes().to_vec(),
            after_position,
        };
        let request = self.authenticated(request);
        Ok(self.inner.subscribe_events(request).await?.into_inner())
    }

    pub async fn read_events(
        &mut self,
        session_id: uuid::Uuid,
        after_position: u64,
        page_size: u32,
    ) -> Result<v1::ReadEventsResponse, ClientError> {
        let negotiation_id = self.negotiation_id().await?;
        let request = v1::ReadEventsRequest {
            metadata: Some(current_metadata(negotiation_id, &["events.replay.v1"])),
            session_id: session_id.as_bytes().to_vec(),
            after_position,
            page_size,
        };
        let request = self.authenticated(request);
        Ok(self.inner.read_events(request).await?.into_inner())
    }

    fn authenticated<T>(&self, value: T) -> Request<T> {
        let mut request = Request::new(value);
        request
            .metadata_mut()
            .insert(AUTHENTICATION_HEADER, self.credential.clone());
        request
    }

    async fn negotiation_id(&mut self) -> Result<Vec<u8>, ClientError> {
        if let Some(value) = &self.negotiation_id {
            return Ok(value.clone());
        }
        let response = self.negotiate().await?;
        match response.outcome {
            Some(v1::negotiate_response::Outcome::Negotiated(value)) => Ok(value.negotiation_id),
            Some(v1::negotiate_response::Outcome::Failure(value)) => {
                Err(Status::failed_precondition(value.message).into())
            }
            None => Err(Status::internal("negotiation response has no outcome").into()),
        }
    }
}
