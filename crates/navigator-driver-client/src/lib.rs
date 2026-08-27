#![cfg(unix)]

use std::{
    fmt,
    io::{self, Read, Write},
    net::Shutdown,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixStream,
    },
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use navigator_driver_protocol::{
    MAX_FRAME_BYTES, PROTOCOL_V1, Validate, authentication_tag, canonical_request_digest, v1,
};
use prost::Message;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub struct DriverCredential(Vec<u8>);

impl DriverCredential {
    pub fn new(secret: Vec<u8>) -> Result<Self, ClientError> {
        if secret.len() < 32 || secret.len() > 4_096 {
            return Err(ClientError::Credential);
        }
        Ok(Self(secret))
    }
}

impl fmt::Debug for DriverCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DriverCredential(<redacted>)")
    }
}

#[derive(Error)]
pub enum ClientError {
    #[error("Driver control I/O failed")]
    Io(#[from] io::Error),
    #[error("Driver control protocol failed")]
    Protocol,
    #[error("Driver control protocol failed at {0}")]
    ProtocolDetail(&'static str),
    #[error("Driver response correlation failed")]
    Correlation,
    #[error("Driver credential is invalid")]
    Credential,
    #[error("Driver returned a typed failure")]
    Failure(v1::Failure),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Observation {
    Event(Box<v1::DriverEvent>),
    NoEvent,
}

impl std::ops::Deref for Observation {
    type Target = v1::DriverEvent;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Event(event) => event,
            Self::NoEvent => panic!("expected DriverEvent, received NoEvent"),
        }
    }
}

impl fmt::Debug for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => formatter.debug_tuple("Io").field(&error.kind()).finish(),
            Self::Failure(value) => formatter
                .debug_struct("Failure")
                .field("code", &value.code)
                .finish_non_exhaustive(),
            Self::Protocol => formatter.write_str("Protocol"),
            Self::ProtocolDetail(stage) => formatter.debug_tuple("Protocol").field(stage).finish(),
            Self::Correlation => formatter.write_str("Correlation"),
            Self::Credential => formatter.write_str("Credential"),
        }
    }
}

pub struct DriverClient {
    stream: UnixStream,
    credential: DriverCredential,
}

pub struct StartParameters {
    pub request_id: Vec<u8>,
    pub participant_id: Vec<u8>,
    pub launch_attempt_id: Vec<u8>,
    pub instance_id: Vec<u8>,
    pub session_id: Vec<u8>,
    pub ownership_epoch: u64,
    pub trusted_configuration: Vec<u8>,
}

impl DriverClient {
    pub fn set_io_timeout(&self, timeout: Duration) -> Result<(), ClientError> {
        self.stream.set_read_timeout(Some(timeout))?;
        self.stream.set_write_timeout(Some(timeout))?;
        Ok(())
    }

    pub fn connect(
        path: &Path,
        credential: DriverCredential,
        timeout: Duration,
    ) -> Result<Self, ClientError> {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(ClientError::Protocol);
        }
        let parent = path.parent().ok_or(ClientError::Protocol)?;
        let parent_metadata = std::fs::symlink_metadata(parent)?;
        if parent_metadata.file_type().is_symlink()
            || !parent_metadata.is_dir()
            || parent_metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != parent_metadata.uid()
        {
            return Err(ClientError::Protocol);
        }
        let stream = UnixStream::connect(path)?;
        let connected = std::fs::symlink_metadata(path)?;
        if connected.dev() != metadata.dev()
            || connected.ino() != metadata.ino()
            || connected.uid() != metadata.uid()
            || connected.permissions().mode() & 0o077 != 0
        {
            return Err(ClientError::Protocol);
        }
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        Ok(Self { stream, credential })
    }

    /// Opens an independent authenticated channel to the same Driver.
    ///
    /// Long-poll Observe traffic must not head-of-line block Stop, Cancel, or
    /// mailbox control calls on another channel.
    pub fn connect_peer(&self, path: &Path, timeout: Duration) -> Result<Self, ClientError> {
        Self::connect(path, DriverCredential(self.credential.0.clone()), timeout)
    }

    pub fn describe(&mut self) -> Result<v1::DescribeResult, ClientError> {
        let response = self.call(v1::envelope::Body::DescribeRequest(v1::DescribeRequest {
            metadata: Some(self.metadata(None)?),
        }))?;
        let v1::envelope::Body::DescribeResponse(response) = response else {
            return Err(ClientError::Protocol);
        };
        match response.result.ok_or(ClientError::Protocol)? {
            v1::describe_response::Result::Success(value) => Ok(value),
            v1::describe_response::Result::Failure(value) => Err(ClientError::Failure(value)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn start(
        &mut self,
        request_id: Vec<u8>,
        participant_id: Vec<u8>,
        launch_attempt_id: Vec<u8>,
        instance_id: Vec<u8>,
        session_id: Vec<u8>,
        ownership_epoch: u64,
        trusted_configuration: Vec<u8>,
    ) -> Result<v1::StartResult, ClientError> {
        self.start_requiring(
            StartParameters {
                request_id,
                participant_id,
                launch_attempt_id,
                instance_id,
                session_id,
                ownership_epoch,
                trusted_configuration,
            },
            Vec::new(),
        )
    }

    pub fn start_requiring(
        &mut self,
        parameters: StartParameters,
        required_capabilities: Vec<v1::CapabilityRequirement>,
    ) -> Result<v1::StartResult, ClientError> {
        let response = self.call(v1::envelope::Body::StartRequest(v1::StartRequest {
            metadata: Some(v1::MutationMetadata {
                request: Some(
                    self.metadata_requiring(Some(parameters.request_id), required_capabilities)?,
                ),
            }),
            participant_id: parameters.participant_id,
            launch_attempt_id: parameters.launch_attempt_id,
            instance_id: parameters.instance_id,
            trusted_configuration: parameters.trusted_configuration,
            session_id: parameters.session_id,
            ownership_epoch: parameters.ownership_epoch,
        }))?;
        let v1::envelope::Body::StartResponse(response) = response else {
            return Err(ClientError::Protocol);
        };
        match response.result.ok_or(ClientError::Protocol)? {
            v1::start_response::Result::Success(value) => Ok(value),
            v1::start_response::Result::Failure(value) => Err(ClientError::Failure(value)),
        }
    }

    pub fn deliver(
        &mut self,
        request_id: Vec<u8>,
        instance: v1::InstanceIdentity,
        message_id: Vec<u8>,
        operation_id: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<v1::Acceptance, ClientError> {
        self.deliver_attempt(
            request_id,
            instance,
            message_id.clone(),
            message_id,
            operation_id,
            payload,
        )
    }

    pub fn deliver_attempt(
        &mut self,
        request_id: Vec<u8>,
        instance: v1::InstanceIdentity,
        message_id: Vec<u8>,
        delivery_attempt_id: Vec<u8>,
        operation_id: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<v1::Acceptance, ClientError> {
        let expected_message_id = message_id.clone();
        let expected_attempt_id = delivery_attempt_id.clone();
        let response = self.call(v1::envelope::Body::DeliverRequest(v1::DeliverRequest {
            metadata: Some(v1::MutationMetadata {
                request: Some(self.metadata(Some(request_id))?),
            }),
            instance: Some(instance),
            message_id,
            delivery_attempt_id,
            operation_id,
            payload,
            pending_correlations: Vec::new(),
        }))?;
        let v1::envelope::Body::DeliverResponse(response) = response else {
            return Err(ClientError::Protocol);
        };
        match response.result.ok_or(ClientError::Protocol)? {
            v1::deliver_response::Result::Success(value)
                if value.message_id == expected_message_id
                    && value.delivery_attempt_id == expected_attempt_id =>
            {
                v1::Acceptance::try_from(value.acceptance).map_err(|_| ClientError::Protocol)
            }
            v1::deliver_response::Result::Success(_) => Err(ClientError::Correlation),
            v1::deliver_response::Result::Failure(value) => Err(ClientError::Failure(value)),
        }
    }

    pub fn observe(
        &mut self,
        instance: v1::InstanceIdentity,
        after_sequence: u64,
    ) -> Result<Observation, ClientError> {
        let response = self.call(v1::envelope::Body::ObserveRequest(v1::ObserveRequest {
            metadata: Some(self.metadata(None)?),
            instance: Some(instance),
            after_sequence,
        }))?;
        match response {
            v1::envelope::Body::Event(event) => Ok(Observation::Event(Box::new(event))),
            v1::envelope::Body::ObserveResponse(response) => match response.result {
                Some(v1::observe_response::Result::Event(event)) => Ok(Observation::Event(event)),
                Some(v1::observe_response::Result::NoEvent(_)) => Ok(Observation::NoEvent),
                None => Err(ClientError::Protocol),
            },
            _ => Err(ClientError::Protocol),
        }
    }

    /// Performs one bounded Observe poll without inheriting the deadline of a
    /// previous RPC made on this stateful stream.
    pub fn observe_with_timeout(
        &mut self,
        instance: v1::InstanceIdentity,
        after_sequence: u64,
        timeout: Duration,
    ) -> Result<Observation, ClientError> {
        if let Err(error) = self.set_io_timeout(timeout) {
            let _ = self.stream.shutdown(Shutdown::Both);
            return Err(error);
        }
        let result = self.observe(instance, after_sequence);
        if matches!(
            result,
            Err(ClientError::Io(_)
                | ClientError::Protocol
                | ClientError::ProtocolDetail(_)
                | ClientError::Correlation)
        ) {
            // A failed framed read may already have consumed a length byte or
            // part of the body. Permanently close this stream rather than let
            // a later RPC interpret the remaining bytes as a fresh frame.
            let _ = self.stream.shutdown(Shutdown::Both);
        }
        result
    }

    pub fn inspect(
        &mut self,
        instance: v1::InstanceIdentity,
    ) -> Result<v1::InspectResult, ClientError> {
        let response = self.call(v1::envelope::Body::InspectRequest(v1::InspectRequest {
            metadata: Some(self.metadata(None)?),
            instance: Some(instance),
        }))?;
        let v1::envelope::Body::InspectResponse(response) = response else {
            return Err(ClientError::Protocol);
        };
        match response.result.ok_or(ClientError::Protocol)? {
            v1::inspect_response::Result::Success(value) => Ok(value),
            v1::inspect_response::Result::Failure(value) => Err(ClientError::Failure(value)),
        }
    }

    pub fn hierarchy_result(
        &mut self,
        request_id: Vec<u8>,
        instance: v1::InstanceIdentity,
        hierarchy_request_id: Vec<u8>,
        result: v1::hierarchy_result_request::Result,
    ) -> Result<(), ClientError> {
        let expected = hierarchy_request_id.clone();
        let response = self.call(v1::envelope::Body::HierarchyResultRequest(
            v1::HierarchyResultRequest {
                metadata: Some(v1::MutationMetadata {
                    request: Some(self.metadata(Some(request_id))?),
                }),
                instance: Some(instance),
                hierarchy_request_id,
                result: Some(result),
            },
        ))?;
        let v1::envelope::Body::HierarchyResultResponse(response) = response else {
            return Err(ClientError::Protocol);
        };
        if response.hierarchy_request_id != expected {
            return Err(ClientError::Correlation);
        }
        Ok(())
    }

    pub fn tool_result(
        &mut self,
        request_id: Vec<u8>,
        instance: v1::InstanceIdentity,
        tool_request_id: Vec<u8>,
        result: v1::tool_result_request::Result,
    ) -> Result<(), ClientError> {
        let expected = tool_request_id.clone();
        let response = self.call(v1::envelope::Body::ToolResultRequest(
            v1::ToolResultRequest {
                metadata: Some(v1::MutationMetadata {
                    request: Some(self.metadata(Some(request_id))?),
                }),
                instance: Some(instance),
                tool_request_id,
                result: Some(result),
            },
        ))?;
        let v1::envelope::Body::ToolResultResponse(response) = response else {
            return Err(ClientError::Protocol);
        };
        if response.tool_request_id != expected {
            return Err(ClientError::Correlation);
        }
        Ok(())
    }

    pub fn stop(
        &mut self,
        request_id: Vec<u8>,
        instance: v1::InstanceIdentity,
    ) -> Result<v1::StopDisposition, ClientError> {
        let response = self.call(v1::envelope::Body::StopRequest(v1::StopRequest {
            metadata: Some(v1::MutationMetadata {
                request: Some(self.metadata(Some(request_id))?),
            }),
            instance: Some(instance),
        }))?;
        let v1::envelope::Body::StopResponse(response) = response else {
            return Err(ClientError::Protocol);
        };
        match response.result.ok_or(ClientError::Protocol)? {
            v1::stop_response::Result::Success(result) => {
                let disposition = v1::StopDisposition::try_from(result.disposition)
                    .map_err(|_| ClientError::Protocol)?;
                (disposition != v1::StopDisposition::Unspecified)
                    .then_some(disposition)
                    .ok_or(ClientError::Protocol)
            }
            v1::stop_response::Result::Failure(_) => Err(ClientError::Protocol),
        }
    }

    pub fn cancel(
        &mut self,
        request_id: Vec<u8>,
        instance: v1::InstanceIdentity,
        operation_id: Vec<u8>,
    ) -> Result<v1::CancelDisposition, ClientError> {
        let response = self.call(v1::envelope::Body::CancelRequest(v1::CancelRequest {
            metadata: Some(v1::MutationMetadata {
                request: Some(self.metadata(Some(request_id))?),
            }),
            instance: Some(instance),
            operation_id,
        }))?;
        let v1::envelope::Body::CancelResponse(response) = response else {
            return Err(ClientError::Protocol);
        };
        match response.result.ok_or(ClientError::Protocol)? {
            v1::cancel_response::Result::Success(result) => {
                let disposition = v1::CancelDisposition::try_from(result.disposition)
                    .map_err(|_| ClientError::Protocol)?;
                (disposition != v1::CancelDisposition::Unspecified)
                    .then_some(disposition)
                    .ok_or(ClientError::Protocol)
            }
            v1::cancel_response::Result::Failure(value) => Err(ClientError::Failure(value)),
        }
    }

    pub fn query_acceptance(
        &mut self,
        instance: v1::InstanceIdentity,
        message_id: Vec<u8>,
        delivery_attempt_id: &[u8],
    ) -> Result<v1::Acceptance, ClientError> {
        let response = self.call(v1::envelope::Body::AcceptanceRequest(
            v1::AcceptanceRequest {
                metadata: Some(self.metadata(None)?),
                instance: Some(instance),
                message_id,
                delivery_attempt_id: delivery_attempt_id.to_vec(),
            },
        ))?;
        let v1::envelope::Body::AcceptanceResponse(response) = response else {
            return Err(ClientError::Protocol);
        };
        match response.result.ok_or(ClientError::Protocol)? {
            v1::acceptance_response::Result::Success(value)
                if value.delivery_attempt_id == delivery_attempt_id =>
            {
                v1::Acceptance::try_from(value.acceptance).map_err(|_| ClientError::Protocol)
            }
            v1::acceptance_response::Result::Success(_) => Err(ClientError::Protocol),
            v1::acceptance_response::Result::Failure(value) => Err(ClientError::Failure(value)),
        }
    }

    pub fn reminder(
        &mut self,
        instance: v1::InstanceIdentity,
        request_id: Vec<u8>,
        operation_id: Vec<u8>,
        message_id: Vec<u8>,
    ) -> Result<v1::RemindResult, ClientError> {
        let response = self.call(v1::envelope::Body::RemindRequest(v1::RemindRequest {
            metadata: Some(v1::MutationMetadata {
                request: Some(self.metadata(Some(request_id))?),
            }),
            instance: Some(instance),
            operation_id,
            message_id,
        }))?;
        let v1::envelope::Body::RemindResponse(response) = response else {
            return Err(ClientError::Protocol);
        };
        match response.result.ok_or(ClientError::Protocol)? {
            v1::remind_response::Result::Success(value) => Ok(value),
            v1::remind_response::Result::Failure(value) => Err(ClientError::Failure(value)),
        }
    }

    fn call(&mut self, body: v1::envelope::Body) -> Result<v1::envelope::Body, ClientError> {
        let mut request = v1::Envelope {
            envelope_id: random_id()?,
            response_authenticator: Vec::new(),
            response_to_request_id: Vec::new(),
            body: Some(body),
        };
        sign(&mut request, &self.credential.0)?;
        request
            .validate()
            .map_err(|_| ClientError::ProtocolDetail("request_validation"))?;
        write_frame(&mut self.stream, &request)?;
        let response =
            read_frame(&mut self.stream)?.ok_or(ClientError::ProtocolDetail("response_eof"))?;
        let response = v1::Envelope::decode(response.as_slice())
            .map_err(|_| ClientError::ProtocolDetail("response_decode"))?;
        navigator_driver_protocol::verify_response(&self.credential.0, &response)
            .map_err(|_| ClientError::ProtocolDetail("response_authentication"))?;
        response
            .validate()
            .map_err(|_| ClientError::ProtocolDetail("response_validation"))?;
        let body = response
            .body
            .ok_or(ClientError::ProtocolDetail("response_body"))?;
        // DriverEvent.in_reply_to is the durable causal command (Start or
        // Deliver), not the envelope id of the later polling Observe call.
        // Observe is correlated by its authenticated response request id
        // below; all other response bodies retain envelope correlation.
        if !matches!(body, v1::envelope::Body::Event(_)) {
            let correlation = response_correlation(&body).ok_or(ClientError::Correlation)?;
            if correlation != request.envelope_id {
                return Err(ClientError::Correlation);
            }
        }
        let request_id = request_metadata(&request)
            .ok_or(ClientError::Protocol)?
            .request_id
            .as_slice();
        if response.response_to_request_id != request_id {
            return Err(ClientError::Correlation);
        }
        Ok(body)
    }

    fn metadata(&self, request_id: Option<Vec<u8>>) -> Result<v1::RequestMetadata, ClientError> {
        self.metadata_requiring(request_id, Vec::new())
    }

    fn metadata_requiring(
        &self,
        request_id: Option<Vec<u8>>,
        required_capabilities: Vec<v1::CapabilityRequirement>,
    ) -> Result<v1::RequestMetadata, ClientError> {
        Ok(v1::RequestMetadata {
            protocol_version: PROTOCOL_V1,
            authentication: Some(v1::Authentication {
                key_id: Sha256::digest(&self.credential.0)[..16].to_vec(),
                nonce: random_id()?,
                expires_unix_ms: unix_millis().saturating_add(30_000),
                authenticator: Vec::new(),
                request_digest: Vec::new(),
            }),
            required_capabilities,
            request_id: request_id.unwrap_or(random_id()?),
        })
    }
}

fn sign(envelope: &mut v1::Envelope, secret: &[u8]) -> Result<(), ClientError> {
    let digest = canonical_request_digest(envelope).map_err(|_| ClientError::Protocol)?;
    let envelope_id = envelope.envelope_id.clone();
    let participant_scope = participant_scope(envelope);
    let launch_scope = launch_scope(envelope);
    let metadata = request_metadata_mut(envelope).ok_or(ClientError::Protocol)?;
    metadata
        .authentication
        .as_mut()
        .ok_or(ClientError::Protocol)?
        .request_digest = digest.to_vec();
    let authentication = metadata
        .authentication
        .as_ref()
        .ok_or(ClientError::Protocol)?;
    let tag = authentication_tag(
        secret,
        &envelope_id,
        &metadata.request_id,
        metadata.protocol_version,
        authentication,
        &participant_scope,
        &launch_scope,
    )
    .map_err(|_| ClientError::Protocol)?;
    request_metadata_mut(envelope)
        .unwrap()
        .authentication
        .as_mut()
        .unwrap()
        .authenticator = tag.to_vec();
    Ok(())
}

fn participant_scope(envelope: &v1::Envelope) -> Vec<u8> {
    if let Some(v1::envelope::Body::StartRequest(v)) = &envelope.body {
        return v.participant_id.clone();
    }
    instance(envelope).map_or_else(Vec::new, |v| v.participant_id.clone())
}
fn launch_scope(envelope: &v1::Envelope) -> Vec<u8> {
    if let Some(v1::envelope::Body::StartRequest(v)) = &envelope.body {
        return v.launch_attempt_id.clone();
    }
    instance(envelope).map_or_else(Vec::new, |v| v.launch_attempt_id.clone())
}
fn instance(envelope: &v1::Envelope) -> Option<&v1::InstanceIdentity> {
    use v1::envelope::Body;
    match envelope.body.as_ref()? {
        Body::DeliverRequest(v) => v.instance.as_ref(),
        Body::AcceptanceRequest(v) => v.instance.as_ref(),
        Body::InspectRequest(v) => v.instance.as_ref(),
        Body::ObserveRequest(v) => v.instance.as_ref(),
        Body::RemindRequest(v) => v.instance.as_ref(),
        Body::HierarchyResultRequest(v) => v.instance.as_ref(),
        Body::ToolResultRequest(v) => v.instance.as_ref(),
        Body::CancelRequest(v) => v.instance.as_ref(),
        Body::StopRequest(v) => v.instance.as_ref(),
        _ => None,
    }
}
fn request_metadata_mut(envelope: &mut v1::Envelope) -> Option<&mut v1::RequestMetadata> {
    use v1::envelope::Body;
    match envelope.body.as_mut()? {
        Body::DescribeRequest(v) => v.metadata.as_mut(),
        Body::StartRequest(v) => v.metadata.as_mut()?.request.as_mut(),
        Body::DeliverRequest(v) => v.metadata.as_mut()?.request.as_mut(),
        Body::AcceptanceRequest(v) => v.metadata.as_mut(),
        Body::InspectRequest(v) => v.metadata.as_mut(),
        Body::ObserveRequest(v) => v.metadata.as_mut(),
        Body::RemindRequest(v) => v.metadata.as_mut()?.request.as_mut(),
        Body::HierarchyResultRequest(v) => v.metadata.as_mut()?.request.as_mut(),
        Body::ToolResultRequest(v) => v.metadata.as_mut()?.request.as_mut(),
        Body::CancelRequest(v) => v.metadata.as_mut()?.request.as_mut(),
        Body::StopRequest(v) => v.metadata.as_mut()?.request.as_mut(),
        _ => None,
    }
}
fn request_metadata(envelope: &v1::Envelope) -> Option<&v1::RequestMetadata> {
    use v1::envelope::Body;
    match envelope.body.as_ref()? {
        Body::DescribeRequest(v) => v.metadata.as_ref(),
        Body::StartRequest(v) => v.metadata.as_ref()?.request.as_ref(),
        Body::DeliverRequest(v) => v.metadata.as_ref()?.request.as_ref(),
        Body::AcceptanceRequest(v) => v.metadata.as_ref(),
        Body::InspectRequest(v) => v.metadata.as_ref(),
        Body::ObserveRequest(v) => v.metadata.as_ref(),
        Body::RemindRequest(v) => v.metadata.as_ref()?.request.as_ref(),
        Body::HierarchyResultRequest(v) => v.metadata.as_ref()?.request.as_ref(),
        Body::ToolResultRequest(v) => v.metadata.as_ref()?.request.as_ref(),
        Body::CancelRequest(v) => v.metadata.as_ref()?.request.as_ref(),
        Body::StopRequest(v) => v.metadata.as_ref()?.request.as_ref(),
        _ => None,
    }
}
fn response_correlation(body: &v1::envelope::Body) -> Option<&[u8]> {
    use v1::envelope::Body;
    match body {
        Body::DescribeResponse(v) => Some(&v.in_reply_to),
        Body::StartResponse(v) => Some(&v.in_reply_to),
        Body::DeliverResponse(v) => Some(&v.in_reply_to),
        Body::AcceptanceResponse(v) => Some(&v.in_reply_to),
        Body::InspectResponse(v) => Some(&v.in_reply_to),
        Body::ObserveResponse(v) => Some(&v.in_reply_to),
        Body::RemindResponse(v) => Some(&v.in_reply_to),
        Body::HierarchyResultResponse(v) => Some(&v.in_reply_to),
        Body::ToolResultResponse(v) => Some(&v.in_reply_to),
        Body::CancelResponse(v) => Some(&v.in_reply_to),
        Body::StopResponse(v) => Some(&v.in_reply_to),
        _ => None,
    }
}

fn random_id() -> Result<Vec<u8>, ClientError> {
    let mut bytes = vec![0_u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(ClientError::Protocol);
    }
    Ok(bytes)
}
fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(i64::MAX, |value| {
            i64::try_from(value.as_millis()).unwrap_or(i64::MAX)
        })
}
fn write_frame(stream: &mut UnixStream, value: &v1::Envelope) -> io::Result<()> {
    let body = value.encode_to_vec();
    if body.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame too large",
        ));
    }
    let mut length = body.len();
    loop {
        let mut byte = u8::try_from(length & 0x7f).unwrap();
        length >>= 7;
        if length != 0 {
            byte |= 0x80;
        }
        stream.write_all(&[byte])?;
        if length == 0 {
            break;
        }
    }
    stream.write_all(&body)?;
    stream.flush()
}
fn read_frame(stream: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
    let mut length = 0usize;
    for shift in (0..35).step_by(7) {
        let mut byte = [0];
        match stream.read_exact(&mut byte) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof && shift == 0 => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
        length |= usize::from(byte[0] & 0x7f) << shift;
        if byte[0] & 0x80 == 0 {
            if length > MAX_FRAME_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "frame too large",
                ));
            }
            let mut body = vec![0; length];
            stream.read_exact(&mut body)?;
            return Ok(Some(body));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid frame length",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn authenticated_metadata_preserves_exact_required_capabilities() {
        let (stream, _subject) = UnixStream::pair().expect("pair");
        let client = DriverClient {
            stream,
            credential: DriverCredential::new(vec![7; 32]).unwrap(),
        };
        let requirements = vec![v1::CapabilityRequirement {
            id: "durable.acceptance".into(),
            minimum_version: 3,
            parameters: vec![v1::CapabilityParameter {
                key: "mode".into(),
                value: "strict".into(),
            }],
        }];
        assert_eq!(
            client
                .metadata_requiring(Some(vec![1; 16]), requirements.clone())
                .unwrap()
                .required_capabilities,
            requirements
        );
    }

    #[test]
    fn bounded_reader_accepts_the_exact_limit_and_rejects_before_oversized_allocation() {
        let mut exact = Vec::from([0x80, 0x80, 0x10]);
        exact.resize(exact.len() + MAX_FRAME_BYTES, 0);
        let (mut reader, mut writer) = UnixStream::pair().expect("pair");
        thread::spawn(move || writer.write_all(&exact).expect("write exact frame"));
        assert_eq!(
            read_frame(&mut reader).expect("exact frame").unwrap().len(),
            MAX_FRAME_BYTES
        );

        let (mut reader, mut writer) = UnixStream::pair().expect("pair");
        writer
            .write_all(&[0x81, 0x80, 0x10])
            .expect("oversized prefix");
        assert_eq!(
            read_frame(&mut reader)
                .expect_err("oversized frame accepted")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn forged_valid_shaped_response_without_the_driver_secret_is_rejected() {
        let (client_stream, mut subject_stream) = UnixStream::pair().expect("pair");
        thread::spawn(move || {
            let request = read_frame(&mut subject_stream)
                .expect("request frame")
                .expect("request before EOF");
            let request = v1::Envelope::decode(request.as_slice()).expect("request envelope");
            let response = v1::Envelope {
                envelope_id: vec![9; 16],
                response_authenticator: Vec::new(),
                response_to_request_id: request_metadata(&request).unwrap().request_id.clone(),
                body: Some(v1::envelope::Body::DescribeResponse(v1::DescribeResponse {
                    in_reply_to: request.envelope_id.clone(),
                    result: Some(v1::describe_response::Result::Success(v1::DescribeResult {
                        driver_id: vec![7; 16],
                        implementation: "mutant".into(),
                        implementation_version: "1".into(),
                        protocol: Some(v1::ProtocolRange {
                            minimum: 1,
                            maximum: 1,
                        }),
                        capabilities: Vec::new(),
                    })),
                })),
            };
            assert_eq!(
                response_correlation(response.body.as_ref().unwrap()),
                Some(request.envelope_id.as_slice())
            );
            write_frame(&mut subject_stream, &response).expect("response frame");
        });
        let mut client = DriverClient {
            stream: client_stream,
            credential: DriverCredential::new(vec![1; 32]).expect("credential"),
        };
        assert!(matches!(
            client.describe(),
            Err(ClientError::ProtocolDetail("response_authentication"))
        ));
    }

    #[test]
    fn observe_keeps_event_causality_separate_from_rpc_correlation() {
        for mutant in ["valid", "wrong_request", "nil_cause"] {
            let secret = vec![13; 32];
            let server_secret = secret.clone();
            let (client_stream, mut subject_stream) = UnixStream::pair().expect("pair");
            thread::spawn(move || {
                let bytes = read_frame(&mut subject_stream).unwrap().unwrap();
                let request = v1::Envelope::decode(bytes.as_slice()).unwrap();
                let v1::envelope::Body::ObserveRequest(observe) = request.body.as_ref().unwrap()
                else {
                    panic!("observe request")
                };
                let causal = if mutant == "nil_cause" {
                    Vec::new()
                } else {
                    vec![77; 16]
                };
                assert_ne!(causal, request.envelope_id);
                let mut response = v1::Envelope {
                    envelope_id: vec![9; 16],
                    response_authenticator: Vec::new(),
                    response_to_request_id: if mutant == "wrong_request" {
                        vec![99; 16]
                    } else {
                        request_metadata(&request).unwrap().request_id.clone()
                    },
                    body: Some(v1::envelope::Body::Event(v1::DriverEvent {
                        event_id: vec![8; 16],
                        instance: observe.instance.clone(),
                        sequence: 1,
                        in_reply_to: causal,
                        event: Some(v1::driver_event::Event::Ready(v1::Ready {
                            capabilities: Vec::new(),
                        })),
                    })),
                };
                navigator_driver_protocol::sign_response(&server_secret, &mut response).unwrap();
                write_frame(&mut subject_stream, &response).unwrap();
            });
            let mut client = DriverClient {
                stream: client_stream,
                credential: DriverCredential::new(secret).unwrap(),
            };
            let identity = v1::InstanceIdentity {
                driver_id: vec![1; 16],
                participant_id: vec![2; 16],
                launch_attempt_id: vec![3; 16],
                instance_id: vec![4; 16],
                session_id: vec![5; 16],
                ownership_epoch: 1,
            };
            match mutant {
                "valid" => assert!(matches!(
                    client.observe(identity, 0).unwrap(),
                    Observation::Event(event) if event.in_reply_to == vec![77; 16]
                )),
                "wrong_request" => assert!(matches!(
                    client.observe(identity, 0),
                    Err(ClientError::Correlation)
                )),
                "nil_cause" => assert!(matches!(
                    client.observe(identity, 0),
                    Err(ClientError::ProtocolDetail("response_validation"))
                )),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn no_event_requires_exact_authenticated_rpc_correlation() {
        for mutant in ["valid", "wrong_envelope", "wrong_request", "wrong_mac"] {
            let secret = vec![23; 32];
            let server_secret = secret.clone();
            let (client_stream, mut subject_stream) = UnixStream::pair().expect("pair");
            thread::spawn(move || {
                let bytes = read_frame(&mut subject_stream).unwrap().unwrap();
                let request = v1::Envelope::decode(bytes.as_slice()).unwrap();
                assert!(matches!(
                    request.body,
                    Some(v1::envelope::Body::ObserveRequest(_))
                ));
                let mut response = v1::Envelope {
                    envelope_id: vec![9; 16],
                    response_authenticator: Vec::new(),
                    response_to_request_id: if mutant == "wrong_request" {
                        vec![98; 16]
                    } else {
                        request_metadata(&request).unwrap().request_id.clone()
                    },
                    body: Some(v1::envelope::Body::ObserveResponse(v1::ObserveResponse {
                        in_reply_to: if mutant == "wrong_envelope" {
                            vec![99; 16]
                        } else {
                            request.envelope_id.clone()
                        },
                        result: Some(v1::observe_response::Result::NoEvent(v1::NoEvent::default())),
                    })),
                };
                navigator_driver_protocol::sign_response(&server_secret, &mut response).unwrap();
                if mutant == "wrong_mac" {
                    response.response_authenticator[0] ^= 1;
                }
                write_frame(&mut subject_stream, &response).unwrap();
            });
            let mut client = DriverClient {
                stream: client_stream,
                credential: DriverCredential::new(secret).unwrap(),
            };
            let identity = v1::InstanceIdentity {
                driver_id: vec![1; 16],
                participant_id: vec![2; 16],
                launch_attempt_id: vec![3; 16],
                instance_id: vec![4; 16],
                session_id: vec![5; 16],
                ownership_epoch: 1,
            };
            match mutant {
                "valid" => assert_eq!(client.observe(identity, 0).unwrap(), Observation::NoEvent),
                "wrong_envelope" | "wrong_request" => assert!(matches!(
                    client.observe(identity, 0),
                    Err(ClientError::Correlation)
                )),
                "wrong_mac" => assert!(matches!(
                    client.observe(identity, 0),
                    Err(ClientError::ProtocolDetail("response_authentication"))
                )),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn observe_timeout_does_not_inherit_a_prior_rpc_deadline() {
        let secret = vec![29; 32];
        let server_secret = secret.clone();
        let (client_stream, mut subject_stream) = UnixStream::pair().expect("pair");
        thread::spawn(move || {
            let bytes = read_frame(&mut subject_stream).unwrap().unwrap();
            let request = v1::Envelope::decode(bytes.as_slice()).unwrap();
            thread::sleep(Duration::from_millis(30));
            let mut response = v1::Envelope {
                envelope_id: vec![9; 16],
                response_authenticator: Vec::new(),
                response_to_request_id: request_metadata(&request).unwrap().request_id.clone(),
                body: Some(v1::envelope::Body::ObserveResponse(v1::ObserveResponse {
                    in_reply_to: request.envelope_id.clone(),
                    result: Some(v1::observe_response::Result::NoEvent(v1::NoEvent::default())),
                })),
            };
            navigator_driver_protocol::sign_response(&server_secret, &mut response).unwrap();
            write_frame(&mut subject_stream, &response).unwrap();
        });
        let mut client = DriverClient {
            stream: client_stream,
            credential: DriverCredential::new(secret).unwrap(),
        };
        client
            .set_io_timeout(Duration::from_millis(5))
            .expect("short preceding RPC deadline");
        let identity = v1::InstanceIdentity {
            driver_id: vec![1; 16],
            participant_id: vec![2; 16],
            launch_attempt_id: vec![3; 16],
            instance_id: vec![4; 16],
            session_id: vec![5; 16],
            ownership_epoch: 1,
        };
        assert_eq!(
            client
                .observe_with_timeout(identity, 0, Duration::from_secs(1))
                .unwrap(),
            Observation::NoEvent
        );
    }

    #[test]
    fn partial_observe_timeout_closes_the_poisoned_stream() {
        use std::sync::mpsc;

        let (client_stream, mut subject_stream) = UnixStream::pair().expect("pair");
        let (eof_tx, eof_rx) = mpsc::channel();
        thread::spawn(move || {
            read_frame(&mut subject_stream).unwrap().unwrap();
            // Declare a ten-byte frame, but never finish it before the client
            // deadline. This leaves framing ambiguous unless the stream dies.
            subject_stream.write_all(&[10]).unwrap();
            thread::sleep(Duration::from_millis(50));
            let mut byte = [0_u8; 1];
            eof_tx
                .send(subject_stream.read(&mut byte).unwrap() == 0)
                .unwrap();
        });
        let mut client = DriverClient {
            stream: client_stream,
            credential: DriverCredential::new(vec![31; 32]).unwrap(),
        };
        let identity = v1::InstanceIdentity {
            driver_id: vec![1; 16],
            participant_id: vec![2; 16],
            launch_attempt_id: vec![3; 16],
            instance_id: vec![4; 16],
            session_id: vec![5; 16],
            ownership_epoch: 1,
        };
        assert!(matches!(
            client.observe_with_timeout(identity, 0, Duration::from_millis(10)),
            Err(ClientError::Io(_))
        ));
        assert!(eof_rx.recv_timeout(Duration::from_secs(1)).unwrap());
    }

    #[test]
    fn acceptance_query_is_signed_and_rejects_a_wrong_attempt_echo() {
        let secret = vec![3; 32];
        let server_secret = secret.clone();
        let (client_stream, mut subject_stream) = UnixStream::pair().expect("pair");
        thread::spawn(move || {
            let request = read_frame(&mut subject_stream)
                .expect("request frame")
                .expect("request before EOF");
            let request = v1::Envelope::decode(request.as_slice()).expect("request envelope");
            navigator_driver_protocol::verify_envelope_authentication(
                &server_secret,
                &request,
                &[2; 16],
                &[3; 16],
                unix_millis(),
                &mut navigator_driver_protocol::ReplayGuard::new(1).expect("replay guard"),
            )
            .expect("signed acceptance request");
            let mut response = v1::Envelope {
                envelope_id: vec![9; 16],
                response_authenticator: Vec::new(),
                response_to_request_id: request_metadata(&request).unwrap().request_id.clone(),
                body: Some(v1::envelope::Body::AcceptanceResponse(
                    v1::AcceptanceResponse {
                        in_reply_to: request.envelope_id.clone(),
                        result: Some(v1::acceptance_response::Result::Success(
                            v1::AcceptanceResult {
                                acceptance: v1::Acceptance::Accepted as i32,
                                delivery_attempt_id: vec![8; 16],
                            },
                        )),
                    },
                )),
            };
            navigator_driver_protocol::sign_response(&server_secret, &mut response)
                .expect("signed response");
            write_frame(&mut subject_stream, &response).expect("response frame");
        });
        let mut client = DriverClient {
            stream: client_stream,
            credential: DriverCredential::new(secret).expect("credential"),
        };
        let identity = v1::InstanceIdentity {
            driver_id: vec![1; 16],
            participant_id: vec![2; 16],
            launch_attempt_id: vec![3; 16],
            instance_id: vec![4; 16],
            session_id: vec![5; 16],
            ownership_epoch: 1,
        };
        assert!(matches!(
            client.query_acceptance(identity, vec![6; 16], &[7; 16]),
            Err(ClientError::Protocol | ClientError::Correlation)
        ));
    }

    #[test]
    fn delivery_rejects_wrong_message_and_attempt_echoes() {
        for wrong_message in [true, false] {
            let secret = vec![4; 32];
            let server_secret = secret.clone();
            let (client_stream, mut subject_stream) = UnixStream::pair().expect("pair");
            thread::spawn(move || {
                let request = read_frame(&mut subject_stream)
                    .expect("request frame")
                    .expect("request before EOF");
                let request = v1::Envelope::decode(request.as_slice()).expect("request envelope");
                let Some(v1::envelope::Body::DeliverRequest(deliver)) = request.body.as_ref()
                else {
                    panic!("deliver request");
                };
                let mut response = v1::Envelope {
                    envelope_id: vec![9; 16],
                    response_authenticator: Vec::new(),
                    response_to_request_id: request_metadata(&request).unwrap().request_id.clone(),
                    body: Some(v1::envelope::Body::DeliverResponse(v1::DeliverResponse {
                        in_reply_to: request.envelope_id.clone(),
                        result: Some(v1::deliver_response::Result::Success(v1::DeliverResult {
                            acceptance: v1::Acceptance::Accepted as i32,
                            message_id: if wrong_message {
                                vec![8; 16]
                            } else {
                                deliver.message_id.clone()
                            },
                            delivery_attempt_id: if wrong_message {
                                deliver.delivery_attempt_id.clone()
                            } else {
                                vec![8; 16]
                            },
                        })),
                    })),
                };
                navigator_driver_protocol::sign_response(&server_secret, &mut response)
                    .expect("signed response");
                write_frame(&mut subject_stream, &response).expect("response frame");
            });
            let mut client = DriverClient {
                stream: client_stream,
                credential: DriverCredential::new(secret).expect("credential"),
            };
            let identity = v1::InstanceIdentity {
                driver_id: vec![1; 16],
                participant_id: vec![2; 16],
                launch_attempt_id: vec![3; 16],
                instance_id: vec![4; 16],
                session_id: vec![5; 16],
                ownership_epoch: 1,
            };
            assert!(matches!(
                client.deliver_attempt(
                    vec![6; 16],
                    identity,
                    vec![7; 16],
                    vec![6; 16],
                    Vec::new(),
                    b"payload".to_vec(),
                ),
                Err(ClientError::Correlation)
            ));
        }
    }

    #[test]
    fn tool_result_request_metadata_and_response_correlations_are_wired() {
        let instance = v1::InstanceIdentity {
            driver_id: vec![1; 16],
            participant_id: vec![2; 16],
            launch_attempt_id: vec![3; 16],
            instance_id: vec![4; 16],
            session_id: vec![5; 16],
            ownership_epoch: 1,
        };
        let mut envelope = v1::Envelope {
            envelope_id: vec![6; 16],
            response_authenticator: Vec::new(),
            response_to_request_id: Vec::new(),
            body: Some(v1::envelope::Body::ToolResultRequest(
                v1::ToolResultRequest {
                    metadata: Some(v1::MutationMetadata {
                        request: Some(v1::RequestMetadata {
                            protocol_version: PROTOCOL_V1,
                            authentication: None,
                            required_capabilities: Vec::new(),
                            request_id: vec![7; 16],
                        }),
                    }),
                    instance: Some(instance),
                    tool_request_id: vec![8; 16],
                    result: Some(v1::tool_result_request::Result::Success(
                        v1::ToolCallResult {
                            output: b"{}".to_vec(),
                            artifacts: vec![],
                        },
                    )),
                },
            )),
        };
        assert!(request_metadata(&envelope).is_some());
        assert!(request_metadata_mut(&mut envelope).is_some());
        let response = v1::envelope::Body::ToolResultResponse(v1::ToolResultResponse {
            in_reply_to: vec![6; 16],
            tool_request_id: vec![8; 16],
        });
        assert_eq!(
            response_correlation(&response),
            Some(vec![6; 16].as_slice())
        );
    }
}
