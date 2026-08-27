use std::fmt::Write as FmtWrite;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use navigator_driver_protocol::{
    MAX_FRAME_BYTES, ReplayGuard, Validate, ValidationError, authentication_tag,
    require_capabilities, sign_response, v1, verify_envelope_authentication,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const CREDENTIAL_FILE_ENV: &str = "NAVIGATOR_FAKE_DRIVER_CREDENTIAL_FILE";
pub const SCENARIO_FILE_ENV: &str = "NAVIGATOR_FAKE_DRIVER_SCENARIO_FILE";
pub const JOURNAL_FILE_ENV: &str = "NAVIGATOR_FAKE_DRIVER_JOURNAL_FILE";
pub const EFFECT_FILE_ENV: &str = "NAVIGATOR_FAKE_DRIVER_EFFECT_FILE";
/// Test-only crash barrier: after durable acceptance, wait for this file before
/// taking the configured crash boundary. This lets a black-box harness crash
/// Navigator itself while the Driver call is still in flight.
pub const DURABLE_ACCEPTANCE_CRASH_BARRIER_ENV: &str =
    "NAVIGATOR_FAKE_DRIVER_DURABLE_ACCEPTANCE_CRASH_BARRIER";
pub const DEFAULT_CAPABILITY_IDS: [&str; 2] = ["durable.acceptance", "graceful.cancellation"];
pub const CONTROL_SOCKET_ENV: &str = "NAVIGATOR_FAKE_DRIVER_CONTROL_SOCKET";
pub const EXIT_CRASH: i32 = 70;
pub const MAX_SCENARIO_BYTES: usize = 64 * 1024;
pub const MAX_SCENARIO_ITEMS: usize = 1_024;
pub const MAX_SCENARIO_STRING_BYTES: usize = 4_096;
pub const MAX_PERSISTED_NONCES: usize = 4_096;
pub const MAX_JOURNAL_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CREDENTIAL_BYTES: usize = 4_096;
const MIN_CREDENTIAL_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryFault {
    #[default]
    None,
    CrashBeforeAcceptance,
    CrashAfterDurableAcceptance,
    RestartAfterDurableAcceptance,
    CrashAfterVolatileReceipt,
    Disconnect,
    Hang,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum JournalFault {
    #[default]
    None,
    BeforeIntentTempWrite,
    AfterIntentTempWrite,
    AfterIntentTempFsync,
    AfterIntentRename,
    AfterIntentParentFsync,
    BeforeTempWrite,
    AfterTempWrite,
    AfterTempFsync,
    AfterRename,
    AfterParentFsync,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Scenario {
    #[serde(default = "default_capabilities")]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub delivery_fault: DeliveryFault,
    #[serde(default)]
    pub journal_fault: JournalFault,
    #[serde(default)]
    pub inspect_states: Vec<String>,
    #[serde(default)]
    pub events: Vec<ScenarioEvent>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScenarioEvent {
    SpawnChild {
        request_id: String,
        template_id: String,
        task_input: String,
    },
    Send {
        request_id: String,
        destination_participant_id: String,
        validated_envelope: String,
        #[serde(default)]
        wait_for_file: Option<String>,
    },
    Status {
        request_id: String,
        participant_id: String,
        operation_id: Option<String>,
    },
    Cancel {
        request_id: String,
        participant_id: String,
        operation_id: String,
    },
    Question {
        operation_id: String,
        message_id: String,
        #[serde(default)]
        delivery_attempt_id: Option<String>,
        code: String,
    },
    Progress {
        operation_id: String,
        message_id: String,
        #[serde(default)]
        delivery_attempt_id: Option<String>,
        payload: String,
    },
    Outcome {
        operation_id: String,
        message_id: String,
        #[serde(default)]
        delivery_attempt_id: Option<String>,
        outcome: String,
        #[serde(default)]
        wait_for_file: Option<String>,
    },
    Disconnected {
        reason: String,
        ownership_lost: bool,
    },
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            capabilities: default_capabilities(),
            delivery_fault: DeliveryFault::None,
            journal_fault: JournalFault::None,
            inspect_states: vec!["idle".into()],
            events: Vec::new(),
        }
    }
}

fn default_capabilities() -> Vec<String> {
    DEFAULT_CAPABILITY_IDS
        .into_iter()
        .map(str::to_owned)
        .collect()
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct BindingRecord {
    driver_id: Vec<u8>,
    participant_id: Vec<u8>,
    launch_attempt_id: Vec<u8>,
    instance_id: Vec<u8>,
    session_id: Vec<u8>,
    ownership_epoch: u64,
}

impl BindingRecord {
    fn wire(&self) -> v1::InstanceIdentity {
        v1::InstanceIdentity {
            driver_id: self.driver_id.clone(),
            participant_id: self.participant_id.clone(),
            launch_attempt_id: self.launch_attempt_id.clone(),
            instance_id: self.instance_id.clone(),
            session_id: self.session_id.clone(),
            ownership_epoch: self.ownership_epoch,
        }
    }

    fn matches(&self, value: &v1::InstanceIdentity) -> bool {
        self == &Self {
            driver_id: value.driver_id.clone(),
            participant_id: value.participant_id.clone(),
            launch_attempt_id: value.launch_attempt_id.clone(),
            instance_id: value.instance_id.clone(),
            session_id: value.session_id.clone(),
            ownership_epoch: value.ownership_epoch,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AcceptedRecord {
    payload_digest: [u8; 32],
    operation_id: Vec<u8>,
    delivery_attempt_id: Vec<u8>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Journal {
    binding: Option<BindingRecord>,
    accepted: BTreeMap<String, AcceptedRecord>,
    uncertain: BTreeMap<String, AcceptedRecord>,
    cancelled: BTreeSet<String>,
    used_nonces: BTreeSet<String>,
    delivery_count: u64,
    #[serde(default)]
    acceptance_query_count: u64,
    cancel_count: u64,
    stopped: bool,
    #[serde(default)]
    stop_process_ids: Vec<u32>,
    next_event_sequence: u64,
    #[serde(default)]
    acknowledged_event_sequence: u64,
    #[serde(default)]
    scripted_event_index: usize,
    #[serde(default)]
    pending_scripted_sequence: Option<u64>,
    inspect_index: usize,
    reminder_count: u64,
    #[serde(default)]
    hierarchy_results: BTreeMap<String, [u8; 32]>,
}

impl Journal {
    #[must_use]
    pub const fn native_delivery_count(&self) -> u64 {
        self.delivery_count
    }

    #[must_use]
    pub const fn acceptance_query_count(&self) -> u64 {
        self.acceptance_query_count
    }

    #[must_use]
    pub const fn native_cancel_count(&self) -> u64 {
        self.cancel_count
    }

    #[must_use]
    pub const fn reminder_count(&self) -> u64 {
        self.reminder_count
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, FakeError> {
        match read_bounded(path.as_ref(), MAX_JOURNAL_BYTES) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(FakeError::Json),
            Err(FakeError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                Ok(Self::default())
            }
            Err(error) => Err(error),
        }
    }

    fn check_nonce(&self, nonce: &str, maximum: usize) -> Result<(), v1::FailureCode> {
        if self.used_nonces.contains(nonce) {
            Err(v1::FailureCode::Authentication)
        } else if self.used_nonces.len() >= maximum {
            Err(v1::FailureCode::Capacity)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Error)]
pub enum FakeError {
    #[error("fake Driver I/O failed")]
    Io(#[from] io::Error),
    #[error("fake Driver JSON is invalid")]
    Json(#[from] serde_json::Error),
    #[error("fake Driver protocol is invalid")]
    Protocol(#[from] ValidationError),
    #[error("fake Driver configuration is invalid")]
    Configuration,
    #[error("fake Driver injected journal crash")]
    InjectedCrash,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessDirective {
    Continue,
    Exit,
    Disconnect,
    Crash,
    Hang,
}

pub struct Engine {
    scenario: Scenario,
    journal: Journal,
    journal_path: PathBuf,
    secret: Vec<u8>,
    key_id: [u8; 16],
    driver_id: [u8; 16],
    events: VecDeque<ScenarioEvent>,
    replay_guard: ReplayGuard,
    effect_path: Option<PathBuf>,
}

impl Engine {
    pub fn open(
        scenario_path: impl AsRef<Path>,
        journal_path: impl AsRef<Path>,
        credential_path: impl AsRef<Path>,
    ) -> Result<Self, FakeError> {
        Self::open_with_driver_id(scenario_path, journal_path, credential_path, None)
    }

    pub fn open_with_driver_id(
        scenario_path: impl AsRef<Path>,
        journal_path: impl AsRef<Path>,
        credential_path: impl AsRef<Path>,
        configured_driver_id: Option<[u8; 16]>,
    ) -> Result<Self, FakeError> {
        validate_credential_file(credential_path.as_ref())?;
        let scenario_path = scenario_path.as_ref().to_owned();
        let scenario_bytes = read_bounded(&scenario_path, MAX_SCENARIO_BYTES)?;
        let scenario: Scenario = serde_json::from_slice(&scenario_bytes)?;
        validate_scenario(&scenario)?;
        let journal_path = journal_path.as_ref().to_owned();
        let journal = Journal::load(&journal_path)?;
        let secret = read_bounded(credential_path.as_ref(), MAX_CREDENTIAL_BYTES)?;
        if secret.len() < MIN_CREDENTIAL_BYTES {
            return Err(FakeError::Configuration);
        }
        let key_id = credential_key_id(&secret);
        let driver_id =
            configured_driver_id.unwrap_or_else(|| derived_id(b"navigator.fake.driver\0", &secret));
        let events = scenario.events.clone().into();
        Ok(Self {
            scenario,
            journal,
            journal_path,
            secret,
            key_id,
            driver_id,
            events,
            replay_guard: ReplayGuard::new(MAX_PERSISTED_NONCES)?,
            effect_path: std::env::var_os(EFFECT_FILE_ENV)
                .or_else(|| std::env::var_os("FAKE_DRIVER_EFFECT_FILE"))
                .map(PathBuf::from),
        })
    }

    pub fn handle(
        &mut self,
        envelope: &v1::Envelope,
        now_unix_ms: i64,
    ) -> Result<(Option<v1::Envelope>, ProcessDirective), FakeError> {
        if let Err(error) = envelope.validate() {
            let code = if matches!(error, ValidationError::UnsupportedVersion) {
                v1::FailureCode::Unsupported
            } else {
                v1::FailureCode::Validation
            };
            let reply = self.failure_reply(envelope, code);
            reply.validate()?;
            return Ok((Some(reply), ProcessDirective::Continue));
        }
        if let Err(error) = self.authenticate(envelope, now_unix_ms) {
            return Ok((
                Some(self.failure_reply(envelope, error)),
                ProcessDirective::Continue,
            ));
        }
        let reply = match envelope.body.as_ref().expect("validated body") {
            v1::envelope::Body::DescribeRequest(_) => self.describe(envelope),
            v1::envelope::Body::StartRequest(request) => self.start(envelope, request)?,
            v1::envelope::Body::InspectRequest(request) => self.inspect(envelope, request)?,
            v1::envelope::Body::DeliverRequest(request) => {
                return self.deliver(envelope, request);
            }
            v1::envelope::Body::AcceptanceRequest(request) => self.acceptance(envelope, request)?,
            v1::envelope::Body::CancelRequest(request) => self.cancel(envelope, request)?,
            v1::envelope::Body::StopRequest(request) => {
                let reply = self.stop(envelope, request)?;
                reply.validate()?;
                return Ok((Some(reply), ProcessDirective::Exit));
            }
            v1::envelope::Body::ObserveRequest(request) => self.observe(envelope, request)?,
            v1::envelope::Body::RemindRequest(request) => self.remind(envelope, request)?,
            v1::envelope::Body::HierarchyResultRequest(request) => {
                self.hierarchy_result(envelope, request)?
            }
            v1::envelope::Body::ToolResultRequest(request) => self.tool_result(envelope, request),
            _ => self.failure_reply(envelope, v1::FailureCode::Validation),
        };
        reply.validate()?;
        Ok((Some(reply), ProcessDirective::Continue))
    }

    fn authenticate(&mut self, envelope: &v1::Envelope, now: i64) -> Result<(), v1::FailureCode> {
        let metadata = request_metadata(envelope).ok_or(v1::FailureCode::Validation)?;
        let auth = metadata
            .authentication
            .as_ref()
            .ok_or(v1::FailureCode::Authentication)?;
        if auth.key_id.as_slice() != self.key_id {
            return Err(v1::FailureCode::Authentication);
        }
        let nonce = hex(&auth.nonce);
        self.journal.check_nonce(&nonce, MAX_PERSISTED_NONCES)?;
        let (participant, launch) = authentication_scope(envelope);
        verify_envelope_authentication(
            &self.secret,
            envelope,
            participant,
            launch,
            now,
            &mut self.replay_guard,
        )
        .map_err(|_| v1::FailureCode::Authentication)?;
        self.journal.used_nonces.insert(nonce);
        self.persist().map_err(|_| v1::FailureCode::Internal)
    }

    fn describe(&self, request: &v1::Envelope) -> v1::Envelope {
        self.reply(
            request,
            v1::envelope::Body::DescribeResponse(v1::DescribeResponse {
                in_reply_to: request.envelope_id.clone(),
                result: Some(v1::describe_response::Result::Success(v1::DescribeResult {
                    driver_id: self.driver_id.to_vec(),
                    implementation: "navigator-deterministic-fake".into(),
                    implementation_version: env!("CARGO_PKG_VERSION").into(),
                    protocol: Some(v1::ProtocolRange {
                        minimum: 1,
                        maximum: 1,
                    }),
                    capabilities: self.capabilities(),
                })),
            }),
        )
    }

    fn start(
        &mut self,
        envelope: &v1::Envelope,
        request: &v1::StartRequest,
    ) -> Result<v1::Envelope, FakeError> {
        let required = request
            .metadata
            .as_ref()
            .and_then(|value| value.request.as_ref())
            .map_or(&[][..], |value| value.required_capabilities.as_slice());
        if require_capabilities(required, &self.capabilities()).is_err() {
            return Ok(self.start_failure(envelope, v1::FailureCode::Unsupported));
        }
        let binding = BindingRecord {
            driver_id: self.driver_id.to_vec(),
            participant_id: request.participant_id.clone(),
            launch_attempt_id: request.launch_attempt_id.clone(),
            instance_id: request.instance_id.clone(),
            session_id: request.session_id.clone(),
            ownership_epoch: request.ownership_epoch,
        };
        if self
            .journal
            .binding
            .as_ref()
            .is_some_and(|value| value != &binding)
        {
            return Ok(self.start_failure(envelope, v1::FailureCode::Conflict));
        }
        self.journal.binding = Some(binding.clone());
        self.journal.stopped = false;
        self.persist()?;
        Ok(self.reply(
            envelope,
            v1::envelope::Body::StartResponse(v1::StartResponse {
                in_reply_to: envelope.envelope_id.clone(),
                result: Some(v1::start_response::Result::Success(v1::StartResult {
                    disposition: v1::StartDisposition::Started as i32,
                    instance: Some(binding.wire()),
                })),
            }),
        ))
    }

    fn inspect(
        &mut self,
        envelope: &v1::Envelope,
        request: &v1::InspectRequest,
    ) -> Result<v1::Envelope, FakeError> {
        if !self.valid_instance(request.instance.as_ref()) {
            return Ok(self.inspect_failure(envelope, v1::FailureCode::Conflict));
        }
        let state = if self.journal.stopped {
            v1::InstanceState::Stopped
        } else {
            let scripted = self
                .scenario
                .inspect_states
                .get(self.journal.inspect_index)
                .map_or("idle", String::as_str);
            self.journal.inspect_index = self.journal.inspect_index.saturating_add(1);
            state(scripted)
        };
        self.persist()?;
        Ok(self.reply(
            envelope,
            v1::envelope::Body::InspectResponse(v1::InspectResponse {
                in_reply_to: envelope.envelope_id.clone(),
                result: Some(v1::inspect_response::Result::Success(v1::InspectResult {
                    state: state as i32,
                    last_event_sequence: self.journal.next_event_sequence,
                })),
            }),
        ))
    }

    fn deliver(
        &mut self,
        envelope: &v1::Envelope,
        request: &v1::DeliverRequest,
    ) -> Result<(Option<v1::Envelope>, ProcessDirective), FakeError> {
        if !self.valid_instance(request.instance.as_ref()) || self.journal.stopped {
            return Ok((
                Some(self.deliver_failure(envelope, v1::FailureCode::Conflict)),
                ProcessDirective::Continue,
            ));
        }
        let key = hex(&request.message_id);
        let digest: [u8; 32] = Sha256::digest(&request.payload).into();
        if let Some(record) = self.journal.accepted.get(&key) {
            let response = if record.payload_digest == digest
                && record.operation_id == request.operation_id
                && record.delivery_attempt_id == request.delivery_attempt_id
            {
                self.deliver_response(envelope, v1::Acceptance::Accepted)
            } else {
                self.deliver_failure(envelope, v1::FailureCode::Conflict)
            };
            return Ok((Some(response), ProcessDirective::Continue));
        }
        if let Some(record) = self.journal.uncertain.get(&key) {
            let response = if record.payload_digest == digest
                && record.operation_id == request.operation_id
                && record.delivery_attempt_id == request.delivery_attempt_id
            {
                self.deliver_response(envelope, v1::Acceptance::Unknown)
            } else {
                self.deliver_failure(envelope, v1::FailureCode::Conflict)
            };
            return Ok((Some(response), ProcessDirective::Continue));
        }
        match self.scenario.delivery_fault {
            DeliveryFault::CrashBeforeAcceptance => Ok((None, ProcessDirective::Crash)),
            DeliveryFault::CrashAfterVolatileReceipt => {
                self.journal.uncertain.insert(
                    key,
                    AcceptedRecord {
                        payload_digest: digest,
                        operation_id: request.operation_id.clone(),
                        delivery_attempt_id: request.delivery_attempt_id.clone(),
                    },
                );
                self.persist_intent()?;
                self.record_external_effect(&request.message_id)?;
                Ok((None, ProcessDirective::Crash))
            }
            DeliveryFault::Disconnect => Ok((None, ProcessDirective::Disconnect)),
            DeliveryFault::Hang => Ok((None, ProcessDirective::Hang)),
            DeliveryFault::None
            | DeliveryFault::CrashAfterDurableAcceptance
            | DeliveryFault::RestartAfterDurableAcceptance => {
                self.journal.uncertain.insert(
                    key.clone(),
                    AcceptedRecord {
                        payload_digest: digest,
                        operation_id: request.operation_id.clone(),
                        delivery_attempt_id: request.delivery_attempt_id.clone(),
                    },
                );
                self.persist_intent()?;
                self.record_external_effect(&request.message_id)?;
                self.journal.uncertain.remove(&key);
                self.journal.accepted.insert(
                    key,
                    AcceptedRecord {
                        payload_digest: digest,
                        operation_id: request.operation_id.clone(),
                        delivery_attempt_id: request.delivery_attempt_id.clone(),
                    },
                );
                self.journal.delivery_count = self.journal.delivery_count.saturating_add(1);
                self.persist_acceptance()?;
                if matches!(
                    self.scenario.delivery_fault,
                    DeliveryFault::CrashAfterDurableAcceptance
                        | DeliveryFault::RestartAfterDurableAcceptance
                ) {
                    if let Some(path) = std::env::var_os(DURABLE_ACCEPTANCE_CRASH_BARRIER_ENV)
                        .or_else(|| {
                            std::env::var_os("FAKE_DRIVER_DURABLE_ACCEPTANCE_CRASH_BARRIER")
                        })
                    {
                        let deadline =
                            std::time::Instant::now() + std::time::Duration::from_secs(5);
                        while !Path::new(&path).is_file() {
                            if std::time::Instant::now() >= deadline {
                                return Err(FakeError::Configuration);
                            }
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        }
                    }
                    return Ok((None, ProcessDirective::Crash));
                }
                Ok((
                    Some(self.deliver_response(envelope, v1::Acceptance::Accepted)),
                    ProcessDirective::Continue,
                ))
            }
        }
    }

    fn acceptance(
        &mut self,
        envelope: &v1::Envelope,
        request: &v1::AcceptanceRequest,
    ) -> Result<v1::Envelope, FakeError> {
        self.journal.acceptance_query_count = self.journal.acceptance_query_count.saturating_add(1);
        self.persist()?;
        if !self.valid_instance(request.instance.as_ref()) {
            return Ok(self.acceptance_failure(envelope, v1::FailureCode::Conflict));
        }
        let key = hex(&request.message_id);
        if self
            .journal
            .accepted
            .get(&key)
            .or_else(|| self.journal.uncertain.get(&key))
            .is_some_and(|record| record.delivery_attempt_id != request.delivery_attempt_id)
        {
            return Ok(self.acceptance_failure(envelope, v1::FailureCode::Conflict));
        }
        let acceptance = if self.journal.accepted.contains_key(&key) {
            v1::Acceptance::Accepted
        } else if self.journal.uncertain.contains_key(&key) {
            v1::Acceptance::Unknown
        } else {
            v1::Acceptance::NotAccepted
        };
        Ok(self.reply(
            envelope,
            v1::envelope::Body::AcceptanceResponse(v1::AcceptanceResponse {
                in_reply_to: envelope.envelope_id.clone(),
                result: Some(v1::acceptance_response::Result::Success(
                    v1::AcceptanceResult {
                        acceptance: acceptance as i32,
                        delivery_attempt_id: request.delivery_attempt_id.clone(),
                    },
                )),
            }),
        ))
    }

    fn cancel(
        &mut self,
        envelope: &v1::Envelope,
        request: &v1::CancelRequest,
    ) -> Result<v1::Envelope, FakeError> {
        if !self.valid_instance(request.instance.as_ref()) {
            return Ok(self.cancel_failure(envelope, v1::FailureCode::Conflict));
        }
        if self.journal.cancelled.insert(hex(&request.operation_id)) {
            self.journal.cancel_count = self.journal.cancel_count.saturating_add(1);
            self.persist()?;
        }
        Ok(self.reply(
            envelope,
            v1::envelope::Body::CancelResponse(v1::CancelResponse {
                in_reply_to: envelope.envelope_id.clone(),
                result: Some(v1::cancel_response::Result::Success(v1::CancelResult {
                    disposition: v1::CancelDisposition::CancelRequested as i32,
                })),
            }),
        ))
    }

    fn stop(
        &mut self,
        envelope: &v1::Envelope,
        request: &v1::StopRequest,
    ) -> Result<v1::Envelope, FakeError> {
        if !self.valid_instance(request.instance.as_ref()) {
            return Ok(self.stop_failure(envelope, v1::FailureCode::Conflict));
        }
        let disposition = if self.journal.stopped {
            v1::StopDisposition::AlreadyStopped
        } else {
            self.journal.stopped = true;
            self.journal.stop_process_ids.push(std::process::id());
            self.persist()?;
            v1::StopDisposition::StoppedConfirmed
        };
        Ok(self.reply(
            envelope,
            v1::envelope::Body::StopResponse(v1::StopResponse {
                in_reply_to: envelope.envelope_id.clone(),
                result: Some(v1::stop_response::Result::Success(v1::StopResult {
                    disposition: disposition as i32,
                })),
            }),
        ))
    }

    fn observe(
        &mut self,
        envelope: &v1::Envelope,
        request: &v1::ObserveRequest,
    ) -> Result<v1::Envelope, FakeError> {
        if !self.valid_instance(request.instance.as_ref()) {
            return Ok(self.failure_reply(envelope, v1::FailureCode::Conflict));
        }
        let has_barrier_event = self
            .events
            .get(self.journal.scripted_event_index)
            .is_some_and(|event| {
                matches!(
                    event,
                    ScenarioEvent::Outcome {
                        wait_for_file: Some(_),
                        ..
                    }
                )
            });
        if request.after_sequence > self.journal.acknowledged_event_sequence.saturating_add(1)
            && !has_barrier_event
        {
            return Ok(self.failure_reply(envelope, v1::FailureCode::Conflict));
        }
        if request.after_sequence > self.journal.acknowledged_event_sequence {
            self.journal.acknowledged_event_sequence = request.after_sequence;
            if self
                .journal
                .pending_scripted_sequence
                .is_some_and(|sequence| request.after_sequence >= sequence)
            {
                self.journal.scripted_event_index =
                    self.journal.scripted_event_index.saturating_add(1);
                self.journal.pending_scripted_sequence = None;
            }
            self.persist()?;
        }
        let sequence = request.after_sequence.saturating_add(1).max(1);
        let scripted = self.events.get(self.journal.scripted_event_index).cloned();
        if let Some(ScenarioEvent::Outcome {
            wait_for_file: Some(path),
            ..
        }) = scripted.as_ref()
            && !Path::new(path).is_file()
        {
            return Ok(self.reply(
                envelope,
                v1::envelope::Body::Event(v1::DriverEvent {
                    event_id: derived_id(b"navigator.fake.waiting\0", &sequence.to_be_bytes())
                        .to_vec(),
                    instance: self.journal.binding.as_ref().map(BindingRecord::wire),
                    sequence,
                    in_reply_to: envelope.envelope_id.clone(),
                    event: Some(v1::driver_event::Event::Ready(v1::Ready {
                        capabilities: self.capabilities(),
                    })),
                }),
            ));
        }
        let wait_for_file = match scripted.as_ref() {
            Some(
                ScenarioEvent::Send { wait_for_file, .. }
                | ScenarioEvent::Outcome { wait_for_file, .. },
            ) => wait_for_file.as_ref(),
            _ => None,
        };
        if let Some(path) = wait_for_file {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !Path::new(path).is_file() {
                if std::time::Instant::now() >= deadline {
                    return Ok(self.failure_reply(envelope, v1::FailureCode::Unavailable));
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
        let delivered_scripted_event = scripted.is_some();
        let mut event = scripted.map_or_else(
            || {
                v1::driver_event::Event::Ready(v1::Ready {
                    capabilities: self.capabilities(),
                })
            },
            scripted_event,
        );
        self.bind_scripted_report_attempt(&mut event)?;
        if delivered_scripted_event {
            self.journal.pending_scripted_sequence = Some(sequence);
        }
        if sequence > self.journal.next_event_sequence {
            self.journal.next_event_sequence = sequence;
            self.persist()?;
        }
        Ok(self.reply(
            envelope,
            v1::envelope::Body::Event(v1::DriverEvent {
                event_id: derived_id(b"navigator.fake.event\0", &sequence.to_be_bytes()).to_vec(),
                instance: self.journal.binding.as_ref().map(BindingRecord::wire),
                sequence,
                event: Some(event),
                in_reply_to: envelope.envelope_id.clone(),
            }),
        ))
    }

    fn bind_scripted_report_attempt(
        &self,
        event: &mut v1::driver_event::Event,
    ) -> Result<(), FakeError> {
        let v1::driver_event::Event::Report(report) = event else {
            return Ok(());
        };
        if report.delivery_attempt_id.is_empty() {
            report.delivery_attempt_id = self
                .journal
                .accepted
                .get(&hex(&report.message_id))
                .map(|record| record.delivery_attempt_id.clone())
                .ok_or(FakeError::Configuration)?;
        }
        Ok(())
    }

    fn remind(
        &mut self,
        envelope: &v1::Envelope,
        request: &v1::RemindRequest,
    ) -> Result<v1::Envelope, FakeError> {
        if !self.valid_instance(request.instance.as_ref()) {
            return Ok(self.failure_reply(envelope, v1::FailureCode::Conflict));
        }
        self.journal.reminder_count = self.journal.reminder_count.saturating_add(1);
        self.persist()?;
        Ok(self.reply(
            envelope,
            v1::envelope::Body::RemindResponse(v1::RemindResponse {
                in_reply_to: envelope.envelope_id.clone(),
                result: Some(v1::remind_response::Result::Success(v1::RemindResult {
                    disposition: v1::RemindDisposition::ReminderRequested as i32,
                })),
            }),
        ))
    }

    fn hierarchy_result(
        &mut self,
        envelope: &v1::Envelope,
        request: &v1::HierarchyResultRequest,
    ) -> Result<v1::Envelope, FakeError> {
        if !self.valid_instance(request.instance.as_ref()) {
            return Ok(self.failure_reply(envelope, v1::FailureCode::Conflict));
        }
        let digest: [u8; 32] = Sha256::digest(request.encode_to_vec()).into();
        let key = hex(&request.hierarchy_request_id);
        match self.journal.hierarchy_results.get(&key) {
            Some(previous) if previous != &digest => {
                return Ok(self.failure_reply(envelope, v1::FailureCode::Conflict));
            }
            Some(_) => {}
            None => {
                self.journal.hierarchy_results.insert(key, digest);
                self.persist()?;
            }
        }
        Ok(self.reply(
            envelope,
            v1::envelope::Body::HierarchyResultResponse(v1::HierarchyResultResponse {
                in_reply_to: envelope.envelope_id.clone(),
                hierarchy_request_id: request.hierarchy_request_id.clone(),
            }),
        ))
    }

    fn valid_instance(&self, value: Option<&v1::InstanceIdentity>) -> bool {
        self.journal
            .binding
            .as_ref()
            .zip(value)
            .is_some_and(|(expected, actual)| expected.matches(actual))
    }

    fn capabilities(&self) -> Vec<v1::Capability> {
        self.scenario
            .capabilities
            .iter()
            .map(|id| v1::Capability {
                id: id.clone(),
                version: 1,
                parameters: Vec::new(),
            })
            .collect()
    }

    fn persist(&self) -> Result<(), FakeError> {
        self.persist_with_fault(JournalFault::None)
    }

    fn persist_acceptance(&self) -> Result<(), FakeError> {
        self.persist_with_fault(self.scenario.journal_fault)
    }

    fn persist_intent(&self) -> Result<(), FakeError> {
        let fault = match self.scenario.journal_fault {
            JournalFault::BeforeIntentTempWrite => JournalFault::BeforeTempWrite,
            JournalFault::AfterIntentTempWrite => JournalFault::AfterTempWrite,
            JournalFault::AfterIntentTempFsync => JournalFault::AfterTempFsync,
            JournalFault::AfterIntentRename => JournalFault::AfterRename,
            JournalFault::AfterIntentParentFsync => JournalFault::AfterParentFsync,
            _ => JournalFault::None,
        };
        self.persist_with_fault(fault)
    }

    fn persist_with_fault(&self, fault: JournalFault) -> Result<(), FakeError> {
        let temporary = self.journal_path.with_extension("tmp");
        let bytes = serde_json::to_vec(&self.journal)?;
        crash_at(fault, JournalFault::BeforeTempWrite)?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        crash_at(fault, JournalFault::AfterTempWrite)?;
        file.sync_all()?;
        crash_at(fault, JournalFault::AfterTempFsync)?;
        fs::rename(temporary, &self.journal_path)?;
        crash_at(fault, JournalFault::AfterRename)?;
        let parent = self.journal_path.parent().ok_or(FakeError::Configuration)?;
        fs::File::open(parent)?.sync_all()?;
        crash_at(fault, JournalFault::AfterParentFsync)?;
        Ok(())
    }

    fn record_external_effect(&self, message_id: &[u8]) -> Result<(), FakeError> {
        let Some(path) = &self.effect_path else {
            return Ok(());
        };
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(file, "{}", hex(message_id))?;
        file.sync_all()?;
        Ok(())
    }

    #[allow(clippy::unused_self)]
    fn reply(&self, request: &v1::Envelope, body: v1::envelope::Body) -> v1::Envelope {
        let mut response = v1::Envelope {
            envelope_id: reply_id(&request.envelope_id),
            response_authenticator: Vec::new(),
            response_to_request_id: request_metadata(request)
                .map_or_else(Vec::new, |metadata| metadata.request_id.clone()),
            body: Some(body),
        };
        sign_response(&self.secret, &mut response).expect("fake response signing cannot fail");
        response
    }

    fn failure_reply(&self, request: &v1::Envelope, code: v1::FailureCode) -> v1::Envelope {
        match request.body.as_ref() {
            Some(v1::envelope::Body::StartRequest(_)) => self.start_failure(request, code),
            Some(v1::envelope::Body::InspectRequest(_)) => self.inspect_failure(request, code),
            Some(v1::envelope::Body::DeliverRequest(_)) => self.deliver_failure(request, code),
            Some(v1::envelope::Body::AcceptanceRequest(_)) => {
                self.acceptance_failure(request, code)
            }
            Some(v1::envelope::Body::CancelRequest(_)) => self.cancel_failure(request, code),
            Some(v1::envelope::Body::StopRequest(_)) => self.stop_failure(request, code),
            Some(v1::envelope::Body::RemindRequest(_)) => self.reply(
                request,
                v1::envelope::Body::RemindResponse(v1::RemindResponse {
                    in_reply_to: request.envelope_id.clone(),
                    result: Some(v1::remind_response::Result::Failure(failure(code))),
                }),
            ),
            _ => self.reply(
                request,
                v1::envelope::Body::DescribeResponse(v1::DescribeResponse {
                    in_reply_to: request.envelope_id.clone(),
                    result: Some(v1::describe_response::Result::Failure(failure(code))),
                }),
            ),
        }
    }

    fn start_failure(&self, request: &v1::Envelope, code: v1::FailureCode) -> v1::Envelope {
        self.reply(
            request,
            v1::envelope::Body::StartResponse(v1::StartResponse {
                in_reply_to: request.envelope_id.clone(),
                result: Some(v1::start_response::Result::Failure(failure(code))),
            }),
        )
    }
    fn inspect_failure(&self, request: &v1::Envelope, code: v1::FailureCode) -> v1::Envelope {
        self.reply(
            request,
            v1::envelope::Body::InspectResponse(v1::InspectResponse {
                in_reply_to: request.envelope_id.clone(),
                result: Some(v1::inspect_response::Result::Failure(failure(code))),
            }),
        )
    }
    fn deliver_failure(&self, request: &v1::Envelope, code: v1::FailureCode) -> v1::Envelope {
        self.reply(
            request,
            v1::envelope::Body::DeliverResponse(v1::DeliverResponse {
                in_reply_to: request.envelope_id.clone(),
                result: Some(v1::deliver_response::Result::Failure(failure(code))),
            }),
        )
    }
    fn deliver_response(&self, request: &v1::Envelope, acceptance: v1::Acceptance) -> v1::Envelope {
        let (message_id, delivery_attempt_id) = match request.body.as_ref() {
            Some(v1::envelope::Body::DeliverRequest(value)) => {
                (value.message_id.clone(), value.delivery_attempt_id.clone())
            }
            _ => (Vec::new(), Vec::new()),
        };
        self.reply(
            request,
            v1::envelope::Body::DeliverResponse(v1::DeliverResponse {
                in_reply_to: request.envelope_id.clone(),
                result: Some(v1::deliver_response::Result::Success(v1::DeliverResult {
                    acceptance: acceptance as i32,
                    message_id,
                    delivery_attempt_id,
                })),
            }),
        )
    }
    fn acceptance_failure(&self, request: &v1::Envelope, code: v1::FailureCode) -> v1::Envelope {
        self.reply(
            request,
            v1::envelope::Body::AcceptanceResponse(v1::AcceptanceResponse {
                in_reply_to: request.envelope_id.clone(),
                result: Some(v1::acceptance_response::Result::Failure(failure(code))),
            }),
        )
    }
    fn cancel_failure(&self, request: &v1::Envelope, code: v1::FailureCode) -> v1::Envelope {
        self.reply(
            request,
            v1::envelope::Body::CancelResponse(v1::CancelResponse {
                in_reply_to: request.envelope_id.clone(),
                result: Some(v1::cancel_response::Result::Failure(failure(code))),
            }),
        )
    }
    fn stop_failure(&self, request: &v1::Envelope, code: v1::FailureCode) -> v1::Envelope {
        self.reply(
            request,
            v1::envelope::Body::StopResponse(v1::StopResponse {
                in_reply_to: request.envelope_id.clone(),
                result: Some(v1::stop_response::Result::Failure(failure(code))),
            }),
        )
    }

    fn tool_result(
        &mut self,
        envelope: &v1::Envelope,
        request: &v1::ToolResultRequest,
    ) -> v1::Envelope {
        if !self.valid_instance(request.instance.as_ref()) {
            return self.failure_reply(envelope, v1::FailureCode::Conflict);
        }
        self.reply(
            envelope,
            v1::envelope::Body::ToolResultResponse(v1::ToolResultResponse {
                in_reply_to: envelope.envelope_id.clone(),
                tool_request_id: request.tool_request_id.clone(),
            }),
        )
    }
}

fn validate_credential_file(path: &Path) -> Result<(), FakeError> {
    let metadata = fs::symlink_metadata(path).map_err(FakeError::Io)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(FakeError::Configuration);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(FakeError::Configuration);
    }
    Ok(())
}

fn crash_at(actual: JournalFault, point: JournalFault) -> Result<(), FakeError> {
    if actual == point {
        Err(FakeError::InjectedCrash)
    } else {
        Ok(())
    }
}

#[must_use]
pub fn canonical_request_digest(envelope: &v1::Envelope) -> [u8; 32] {
    navigator_driver_protocol::canonical_request_digest(envelope)
        .expect("request envelope contains authentication metadata")
}

#[must_use]
pub fn credential_key_id(secret: &[u8]) -> [u8; 16] {
    Sha256::digest(secret)[..16]
        .try_into()
        .expect("SHA-256 prefix is exactly 16 bytes")
}

#[expect(
    clippy::too_many_lines,
    reason = "closed scenario grammar stays in one validator"
)]
fn validate_scenario(scenario: &Scenario) -> Result<(), FakeError> {
    if scenario.capabilities.len() > MAX_SCENARIO_ITEMS
        || scenario.inspect_states.len() > MAX_SCENARIO_ITEMS
        || scenario.events.len() > MAX_SCENARIO_ITEMS
        || scenario
            .capabilities
            .iter()
            .any(|value| value.len() > MAX_SCENARIO_STRING_BYTES)
        || scenario
            .inspect_states
            .iter()
            .any(|value| value.len() > MAX_SCENARIO_STRING_BYTES)
        || scenario.events.iter().any(|event| match event {
            ScenarioEvent::SpawnChild {
                request_id,
                template_id,
                task_input,
            } => {
                request_id.len() > MAX_SCENARIO_STRING_BYTES
                    || template_id.len() > MAX_SCENARIO_STRING_BYTES
                    || task_input.len() > navigator_driver_protocol::MAX_PAYLOAD_BYTES
            }
            ScenarioEvent::Progress {
                operation_id,
                message_id,
                delivery_attempt_id,
                payload,
            } => {
                operation_id.len() > MAX_SCENARIO_STRING_BYTES
                    || message_id.len() > MAX_SCENARIO_STRING_BYTES
                    || delivery_attempt_id
                        .as_ref()
                        .is_some_and(|value| value.len() > MAX_SCENARIO_STRING_BYTES)
                    || payload.len() > MAX_SCENARIO_STRING_BYTES
            }
            ScenarioEvent::Outcome {
                operation_id,
                message_id,
                delivery_attempt_id,
                outcome,
                wait_for_file,
            } => {
                operation_id.len() > MAX_SCENARIO_STRING_BYTES
                    || message_id.len() > MAX_SCENARIO_STRING_BYTES
                    || delivery_attempt_id
                        .as_ref()
                        .is_some_and(|value| value.len() > MAX_SCENARIO_STRING_BYTES)
                    || outcome.len() > MAX_SCENARIO_STRING_BYTES
                    || wait_for_file
                        .as_ref()
                        .is_some_and(|value| value.len() > MAX_SCENARIO_STRING_BYTES)
            }
            ScenarioEvent::Send {
                request_id,
                destination_participant_id,
                validated_envelope,
                wait_for_file,
            } => {
                request_id.len() > MAX_SCENARIO_STRING_BYTES
                    || destination_participant_id.len() > MAX_SCENARIO_STRING_BYTES
                    || validated_envelope.len() > navigator_driver_protocol::MAX_PAYLOAD_BYTES
                    || wait_for_file
                        .as_ref()
                        .is_some_and(|value| value.len() > MAX_SCENARIO_STRING_BYTES)
            }
            ScenarioEvent::Status {
                request_id,
                participant_id,
                operation_id,
            } => {
                request_id.len() > MAX_SCENARIO_STRING_BYTES
                    || participant_id.len() > MAX_SCENARIO_STRING_BYTES
                    || operation_id
                        .as_ref()
                        .is_some_and(|value| value.len() > MAX_SCENARIO_STRING_BYTES)
            }
            ScenarioEvent::Cancel {
                request_id,
                participant_id,
                operation_id,
            } => {
                request_id.len() > MAX_SCENARIO_STRING_BYTES
                    || participant_id.len() > MAX_SCENARIO_STRING_BYTES
                    || operation_id.len() > MAX_SCENARIO_STRING_BYTES
            }
            ScenarioEvent::Question {
                operation_id,
                message_id,
                delivery_attempt_id,
                code,
            } => {
                operation_id.len() > MAX_SCENARIO_STRING_BYTES
                    || message_id.len() > MAX_SCENARIO_STRING_BYTES
                    || delivery_attempt_id
                        .as_ref()
                        .is_some_and(|value| value.len() > MAX_SCENARIO_STRING_BYTES)
                    || code.len() > MAX_SCENARIO_STRING_BYTES
            }
            ScenarioEvent::Disconnected { reason, .. } => reason.len() > MAX_SCENARIO_STRING_BYTES,
        })
    {
        return Err(FakeError::Configuration);
    }
    if scenario.inspect_states.iter().any(|state| {
        !matches!(
            state.as_str(),
            "ready" | "idle" | "busy" | "disconnected" | "failed" | "uncertain"
        )
    }) || scenario.events.iter().any(|event| match event {
        ScenarioEvent::SpawnChild {
            request_id,
            template_id,
            ..
        } => !valid_script_id(request_id) || !valid_script_id(template_id),
        ScenarioEvent::Progress {
            operation_id,
            message_id,
            delivery_attempt_id,
            ..
        } => {
            !valid_script_id(operation_id)
                || !valid_script_id(message_id)
                || delivery_attempt_id
                    .as_ref()
                    .is_some_and(|value| !valid_script_id(value))
        }
        ScenarioEvent::Send {
            request_id,
            destination_participant_id,
            ..
        } => !valid_script_id(request_id) || !valid_script_id(destination_participant_id),
        ScenarioEvent::Status {
            request_id,
            participant_id,
            operation_id,
        } => {
            !valid_script_id(request_id)
                || !valid_script_id(participant_id)
                || operation_id
                    .as_ref()
                    .is_some_and(|value| !valid_script_id(value))
        }
        ScenarioEvent::Cancel {
            request_id,
            participant_id,
            operation_id,
        } => {
            !valid_script_id(request_id)
                || !valid_script_id(participant_id)
                || !valid_script_id(operation_id)
        }
        ScenarioEvent::Question {
            operation_id,
            message_id,
            delivery_attempt_id,
            code,
        } => {
            !valid_script_id(operation_id)
                || !valid_script_id(message_id)
                || delivery_attempt_id
                    .as_ref()
                    .is_some_and(|value| !valid_script_id(value))
                || code.is_empty()
        }
        ScenarioEvent::Outcome {
            operation_id,
            message_id,
            delivery_attempt_id,
            outcome,
            ..
        } => {
            !valid_script_id(operation_id)
                || !valid_script_id(message_id)
                || delivery_attempt_id
                    .as_ref()
                    .is_some_and(|value| !valid_script_id(value))
                || !matches!(
                    outcome.as_str(),
                    "succeeded" | "failed" | "cancelled" | "uncertain"
                )
        }
        ScenarioEvent::Disconnected { .. } => false,
    }) {
        return Err(FakeError::Configuration);
    }
    Ok(())
}

fn valid_script_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|value| !value.is_nil())
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, FakeError> {
    let file = fs::File::open(path)?;
    let limit = u64::try_from(maximum)
        .map_err(|_| FakeError::Configuration)?
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(maximum.min(8 * 1024));
    file.take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(FakeError::Configuration);
    }
    Ok(bytes)
}

pub fn sign_envelope(envelope: &mut v1::Envelope, secret: &[u8]) -> Result<(), ValidationError> {
    let digest = canonical_request_digest(envelope);
    let envelope_id = envelope.envelope_id.clone();
    let (participant, launch) = authentication_scope(envelope);
    let participant = participant.to_vec();
    let launch = launch.to_vec();
    let metadata = request_metadata_mut(envelope).ok_or(ValidationError::Missing("metadata"))?;
    let authentication = metadata
        .authentication
        .as_mut()
        .ok_or(ValidationError::Missing("authentication"))?;
    authentication.request_digest = digest.to_vec();
    authentication.authenticator = authentication_tag(
        secret,
        &envelope_id,
        &metadata.request_id,
        metadata.protocol_version,
        authentication,
        &participant,
        &launch,
    )?
    .to_vec();
    Ok(())
}

pub fn read_frame(reader: &mut impl Read) -> Result<Option<Vec<u8>>, FakeError> {
    let Some(length) = read_varint(reader)? else {
        return Ok(None);
    };
    let length = usize::try_from(length).map_err(|_| ValidationError::FrameTooLarge)?;
    if length > MAX_FRAME_BYTES {
        return Err(ValidationError::FrameTooLarge.into());
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    Ok(Some(bytes))
}

pub fn write_frame(writer: &mut impl Write, envelope: &v1::Envelope) -> Result<(), FakeError> {
    let bytes = envelope.encode_to_vec();
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ValidationError::FrameTooLarge.into());
    }
    write_varint(writer, bytes.len() as u64)?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

fn read_varint(reader: &mut impl Read) -> Result<Option<u64>, FakeError> {
    let mut value = 0_u64;
    for shift in (0..35).step_by(7) {
        let mut byte = [0];
        match reader.read_exact(&mut byte) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof && shift == 0 => {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        }
        value |= u64::from(byte[0] & 0x7f) << shift;
        if byte[0] & 0x80 == 0 {
            return Ok(Some(value));
        }
    }
    Err(ValidationError::FrameTooLarge.into())
}

fn write_varint(writer: &mut impl Write, mut value: u64) -> io::Result<()> {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        writer.write_all(&[byte])?;
        if value == 0 {
            return Ok(());
        }
    }
}

fn request_metadata(envelope: &v1::Envelope) -> Option<&v1::RequestMetadata> {
    use v1::envelope::Body;
    match envelope.body.as_ref()? {
        Body::DescribeRequest(value) => value.metadata.as_ref(),
        Body::StartRequest(value) => value.metadata.as_ref()?.request.as_ref(),
        Body::InspectRequest(value) => value.metadata.as_ref(),
        Body::DeliverRequest(value) => value.metadata.as_ref()?.request.as_ref(),
        Body::AcceptanceRequest(value) => value.metadata.as_ref(),
        Body::CancelRequest(value) => value.metadata.as_ref()?.request.as_ref(),
        Body::StopRequest(value) => value.metadata.as_ref()?.request.as_ref(),
        Body::ObserveRequest(value) => value.metadata.as_ref(),
        Body::RemindRequest(value) => value.metadata.as_ref()?.request.as_ref(),
        Body::HierarchyResultRequest(value) => value.metadata.as_ref()?.request.as_ref(),
        Body::ToolResultRequest(value) => value.metadata.as_ref()?.request.as_ref(),
        _ => None,
    }
}

fn request_metadata_mut(envelope: &mut v1::Envelope) -> Option<&mut v1::RequestMetadata> {
    use v1::envelope::Body;
    match envelope.body.as_mut()? {
        Body::DescribeRequest(value) => value.metadata.as_mut(),
        Body::StartRequest(value) => value.metadata.as_mut()?.request.as_mut(),
        Body::InspectRequest(value) => value.metadata.as_mut(),
        Body::DeliverRequest(value) => value.metadata.as_mut()?.request.as_mut(),
        Body::AcceptanceRequest(value) => value.metadata.as_mut(),
        Body::CancelRequest(value) => value.metadata.as_mut()?.request.as_mut(),
        Body::StopRequest(value) => value.metadata.as_mut()?.request.as_mut(),
        Body::ObserveRequest(value) => value.metadata.as_mut(),
        Body::RemindRequest(value) => value.metadata.as_mut()?.request.as_mut(),
        Body::HierarchyResultRequest(value) => value.metadata.as_mut()?.request.as_mut(),
        Body::ToolResultRequest(value) => value.metadata.as_mut()?.request.as_mut(),
        _ => None,
    }
}

fn authentication_scope(envelope: &v1::Envelope) -> (&[u8], &[u8]) {
    use v1::envelope::Body;
    match envelope.body.as_ref() {
        Some(Body::StartRequest(value)) => (&value.participant_id, &value.launch_attempt_id),
        Some(Body::InspectRequest(value)) => scope_from_instance(value.instance.as_ref()),
        Some(Body::DeliverRequest(value)) => scope_from_instance(value.instance.as_ref()),
        Some(Body::AcceptanceRequest(value)) => scope_from_instance(value.instance.as_ref()),
        Some(Body::CancelRequest(value)) => scope_from_instance(value.instance.as_ref()),
        Some(Body::StopRequest(value)) => scope_from_instance(value.instance.as_ref()),
        Some(Body::ObserveRequest(value)) => scope_from_instance(value.instance.as_ref()),
        Some(Body::RemindRequest(value)) => scope_from_instance(value.instance.as_ref()),
        Some(Body::HierarchyResultRequest(value)) => scope_from_instance(value.instance.as_ref()),
        Some(Body::ToolResultRequest(value)) => scope_from_instance(value.instance.as_ref()),
        _ => (&[], &[]),
    }
}

fn scope_from_instance(value: Option<&v1::InstanceIdentity>) -> (&[u8], &[u8]) {
    value.map_or((&[], &[]), |value| {
        (
            value.participant_id.as_slice(),
            value.launch_attempt_id.as_slice(),
        )
    })
}

fn failure(code: v1::FailureCode) -> v1::Failure {
    v1::Failure {
        code: code as i32,
        message: code.as_str_name().to_owned(),
        retryable: false,
    }
}
fn reply_id(request: &[u8]) -> Vec<u8> {
    derived_id(b"navigator.fake.reply\0", request).to_vec()
}
fn derived_id(domain: &[u8], input: &[u8]) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(domain)
        .chain_update(input)
        .finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    id[6] = (id[6] & 0x0f) | 0x40;
    id[8] = (id[8] & 0x3f) | 0x80;
    id
}
fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
fn state(value: &str) -> v1::InstanceState {
    match value {
        "ready" => v1::InstanceState::Ready,
        "busy" => v1::InstanceState::Busy,
        "disconnected" => v1::InstanceState::Disconnected,
        "failed" => v1::InstanceState::Failed,
        "uncertain" => v1::InstanceState::InstanceUncertain,
        _ => v1::InstanceState::Idle,
    }
}
#[expect(clippy::too_many_lines, reason = "closed scenario event mapping")]
fn scripted_event(value: ScenarioEvent) -> v1::driver_event::Event {
    match value {
        ScenarioEvent::SpawnChild {
            request_id,
            template_id,
            task_input,
        } => v1::driver_event::Event::HierarchyCommand(v1::HierarchyCommand {
            request_id: parse_id(&request_id),
            command: Some(v1::hierarchy_command::Command::SpawnChild(
                v1::SpawnChildCommand {
                    template_id: parse_id(&template_id),
                    task_input: task_input.into_bytes(),
                    grant_id: Vec::new(),
                },
            )),
        }),
        ScenarioEvent::Progress {
            operation_id,
            message_id,
            delivery_attempt_id,
            payload,
        } => v1::driver_event::Event::Report(v1::Report {
            operation_id: parse_id(&operation_id),
            message_id: parse_id(&message_id),
            delivery_attempt_id: delivery_attempt_id
                .map_or_else(Vec::new, |value| parse_id(&value)),
            result: Some(v1::report::Result::Outcome(v1::ReportOutcome {
                kind: v1::ReportKind::Progress as i32,
                payload: payload.into_bytes(),
            })),
        }),
        ScenarioEvent::Send {
            request_id,
            destination_participant_id,
            validated_envelope,
            ..
        } => v1::driver_event::Event::HierarchyCommand(v1::HierarchyCommand {
            request_id: parse_id(&request_id),
            command: Some(v1::hierarchy_command::Command::Send(
                v1::SendMessageCommand {
                    destination_participant_id: parse_id(&destination_participant_id),
                    validated_envelope: validated_envelope.into_bytes(),
                },
            )),
        }),
        ScenarioEvent::Status {
            request_id,
            participant_id,
            operation_id,
        } => v1::driver_event::Event::HierarchyCommand(v1::HierarchyCommand {
            request_id: parse_id(&request_id),
            command: Some(v1::hierarchy_command::Command::Status(
                v1::ParticipantStatusCommand {
                    participant_id: parse_id(&participant_id),
                    operation_id: operation_id.map_or_else(Vec::new, |value| parse_id(&value)),
                },
            )),
        }),
        ScenarioEvent::Cancel {
            request_id,
            participant_id,
            operation_id,
        } => v1::driver_event::Event::HierarchyCommand(v1::HierarchyCommand {
            request_id: parse_id(&request_id),
            command: Some(v1::hierarchy_command::Command::Cancel(
                v1::CancelHierarchyCommand {
                    participant_id: parse_id(&participant_id),
                    operation_id: parse_id(&operation_id),
                },
            )),
        }),
        ScenarioEvent::Question {
            operation_id,
            message_id,
            delivery_attempt_id,
            code,
        } => v1::driver_event::Event::Report(v1::Report {
            operation_id: parse_id(&operation_id),
            message_id: parse_id(&message_id),
            delivery_attempt_id: delivery_attempt_id
                .map_or_else(Vec::new, |value| parse_id(&value)),
            result: Some(v1::report::Result::Outcome(v1::ReportOutcome {
                kind: v1::ReportKind::Question as i32,
                payload: code.into_bytes(),
            })),
        }),
        ScenarioEvent::Outcome {
            operation_id,
            message_id,
            delivery_attempt_id,
            outcome,
            ..
        } => v1::driver_event::Event::Report(v1::Report {
            operation_id: parse_id(&operation_id),
            message_id: parse_id(&message_id),
            delivery_attempt_id: delivery_attempt_id
                .map_or_else(Vec::new, |value| parse_id(&value)),
            result: Some(v1::report::Result::Outcome(v1::ReportOutcome {
                kind: match outcome.as_str() {
                    "succeeded" => v1::ReportKind::Succeeded,
                    "failed" => v1::ReportKind::ReportFailed,
                    "cancelled" => v1::ReportKind::ReportCancelled,
                    _ => v1::ReportKind::ReportUncertain,
                } as i32,
                payload: Vec::new(),
            })),
        }),
        ScenarioEvent::Disconnected {
            reason,
            ownership_lost,
        } => v1::driver_event::Event::Disconnected(v1::Disconnected {
            reason,
            ownership_lost,
        }),
    }
}
fn parse_id(value: &str) -> Vec<u8> {
    uuid::Uuid::parse_str(value).map_or_else(
        |_| derived_id(b"navigator.fake.script-id\0", value.as_bytes()).to_vec(),
        |id| id.as_bytes().to_vec(),
    )
}

#[cfg(test)]
mod tests {
    use super::Journal;
    use navigator_driver_protocol::v1;

    #[test]
    fn bounded_nonce_registry_fails_closed_without_evicting_replay_evidence() {
        let mut journal = Journal::default();
        journal.used_nonces.insert("first".into());
        journal.used_nonces.insert("second".into());

        assert_eq!(
            journal.check_nonce("third", 2),
            Err(v1::FailureCode::Capacity)
        );
        assert_eq!(
            journal.check_nonce("first", 2),
            Err(v1::FailureCode::Authentication)
        );
        assert_eq!(journal.used_nonces.len(), 2);

        let encoded = serde_json::to_vec(&journal).expect("encode journal");
        let reopened: Journal = serde_json::from_slice(&encoded).expect("reopen journal");
        assert_eq!(
            reopened.check_nonce("second", 2),
            Err(v1::FailureCode::Authentication)
        );
        assert_eq!(
            reopened.check_nonce("new", 2),
            Err(v1::FailureCode::Capacity)
        );
    }
}
