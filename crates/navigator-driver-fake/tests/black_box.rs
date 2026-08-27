use navigator_conformance::driver::{
    AcceptanceObservation, CapabilityObservation, DriverDescription, DriverErrorKind,
    DriverSubject, InstanceBinding, InstanceObservation, StopObservation, assert_driver_contract,
    assert_durable_acceptance_contract,
};
use navigator_driver_fake::{
    CREDENTIAL_FILE_ENV, EFFECT_FILE_ENV, EXIT_CRASH, JOURNAL_FILE_ENV, SCENARIO_FILE_ENV,
    sign_envelope,
};
use navigator_driver_protocol::{MAX_FRAME_BYTES, PROTOCOL_V1, v1};
use prost::Message;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    io::{Read, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
fn id(value: u8) -> Vec<u8> {
    vec![value; 16]
}

struct Harness {
    _dir: TempDir,
    scenario: std::path::PathBuf,
    journal: std::path::PathBuf,
    credential: std::path::PathBuf,
    effects: std::path::PathBuf,
}
struct Driver {
    child: Child,
    input: Option<ChildStdin>,
    output: ChildStdout,
}
struct Subject<'a> {
    driver: Driver,
    harness: &'a Harness,
    nonce: u8,
    stopped: bool,
}

impl Harness {
    fn new(fault: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let scenario = dir.path().join("scenario.json");
        let journal = dir.path().join("journal.json");
        let credential = dir.path().join("credential");
        let effects = dir.path().join("effects");
        fs::write(&scenario, format!(r#"{{"delivery_fault":"{fault}"}}"#)).unwrap();
        fs::write(&credential, SECRET).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            _dir: dir,
            scenario,
            journal,
            credential,
            effects,
        }
    }
    fn scenario(&self, fault: &str) {
        fs::write(&self.scenario, format!(r#"{{"delivery_fault":"{fault}"}}"#)).unwrap();
    }
    fn journal_fault(&self, fault: &str) {
        fs::write(&self.scenario, format!(r#"{{"journal_fault":"{fault}"}}"#)).unwrap();
    }
    fn scenario_json(&self, value: &str) {
        fs::write(&self.scenario, value).unwrap();
    }
    fn spawn(&self) -> Driver {
        let mut child = Command::new(env!("CARGO_BIN_EXE_navigator-driver-fake"))
            .env(SCENARIO_FILE_ENV, &self.scenario)
            .env(JOURNAL_FILE_ENV, &self.journal)
            .env(CREDENTIAL_FILE_ENV, &self.credential)
            .env(EFFECT_FILE_ENV, &self.effects)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Driver {
            input: child.stdin.take(),
            output: child.stdout.take().unwrap(),
            child,
        }
    }
    fn effects(&self) -> Vec<String> {
        fs::read_to_string(&self.effects)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

impl Driver {
    fn send(&mut self, envelope: &v1::Envelope) {
        let body = envelope.encode_to_vec();
        write_varint(self.input.as_mut().unwrap(), body.len());
        self.input.as_mut().unwrap().write_all(&body).unwrap();
        self.input.as_mut().unwrap().flush().unwrap();
    }
    fn request(&mut self, envelope: &v1::Envelope) -> v1::Envelope {
        self.send(envelope);
        let size = read_varint(&mut self.output).unwrap();
        let mut body = vec![0; size];
        self.output.read_exact(&mut body).unwrap();
        v1::Envelope::decode(body.as_slice()).unwrap()
    }
    fn close_input(&mut self) {
        self.input.take();
    }
    fn wait_within(&mut self, duration: Duration) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + duration;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_varint(mut writer: impl Write, mut value: usize) {
    loop {
        let mut byte = u8::try_from(value & 0x7f).unwrap();
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        writer.write_all(&[byte]).unwrap();
        if value == 0 {
            return;
        }
    }
}
fn read_varint(mut reader: impl Read) -> Option<usize> {
    let mut value = 0;
    for shift in (0..35).step_by(7) {
        let mut byte = [0];
        reader.read_exact(&mut byte).ok()?;
        value |= usize::from(byte[0] & 0x7f) << shift;
        if byte[0] & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

fn metadata(nonce: u8, expires: i64) -> v1::RequestMetadata {
    v1::RequestMetadata {
        protocol_version: PROTOCOL_V1,
        authentication: Some(v1::Authentication {
            key_id: navigator_driver_fake::credential_key_id(SECRET).to_vec(),
            nonce: id(nonce),
            expires_unix_ms: expires,
            authenticator: vec![],
            request_digest: vec![],
        }),
        required_capabilities: vec![],
        request_id: id(nonce.wrapping_add(80)),
    }
}
fn expiry() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
        + 60_000
}
fn signed(body: v1::envelope::Body, envelope: u8, nonce: u8) -> v1::Envelope {
    let mut value = v1::Envelope {
        envelope_id: id(envelope),
        response_authenticator: Vec::new(),
        response_to_request_id: Vec::new(),
        body: Some(body),
    };
    let meta = match value.body.as_mut().unwrap() {
        v1::envelope::Body::DescribeRequest(v) => v.metadata.as_mut().unwrap(),
        v1::envelope::Body::StartRequest(v) => {
            v.metadata.as_mut().unwrap().request.as_mut().unwrap()
        }
        v1::envelope::Body::DeliverRequest(v) => {
            v.metadata.as_mut().unwrap().request.as_mut().unwrap()
        }
        v1::envelope::Body::AcceptanceRequest(v) => v.metadata.as_mut().unwrap(),
        v1::envelope::Body::InspectRequest(v) => v.metadata.as_mut().unwrap(),
        v1::envelope::Body::CancelRequest(v) => {
            v.metadata.as_mut().unwrap().request.as_mut().unwrap()
        }
        v1::envelope::Body::StopRequest(v) => {
            v.metadata.as_mut().unwrap().request.as_mut().unwrap()
        }
        v1::envelope::Body::ObserveRequest(v) => v.metadata.as_mut().unwrap(),
        _ => unreachable!(),
    };
    *meta = metadata(nonce, expiry());
    sign_envelope(&mut value, SECRET).unwrap();
    value
}
fn describe(n: u8) -> v1::Envelope {
    signed(
        v1::envelope::Body::DescribeRequest(v1::DescribeRequest {
            metadata: Some(metadata(n, expiry())),
        }),
        n,
        n,
    )
}
fn start(n: u8) -> v1::Envelope {
    start_with_instance(n, 5)
}
fn start_with_instance(n: u8, instance: u8) -> v1::Envelope {
    signed(
        v1::envelope::Body::StartRequest(v1::StartRequest {
            metadata: Some(v1::MutationMetadata {
                request: Some(metadata(n, expiry())),
            }),
            participant_id: id(2),
            launch_attempt_id: id(3),
            instance_id: id(instance),
            trusted_configuration: vec![],
            session_id: id(4),
            ownership_epoch: 1,
        }),
        n,
        n,
    )
}

#[test]
fn start_binds_navigator_instance_and_rejects_changed_retry() {
    let harness = Harness::new("none");
    let mut driver = harness.spawn();
    let first = binding(&driver.request(&start_with_instance(60, 5)));
    assert_eq!(first.instance_id, id(5));

    let repeated = binding(&driver.request(&start_with_instance(61, 5)));
    assert_eq!(repeated.instance_id, id(5));

    let conflict = driver.request(&start_with_instance(62, 6));
    let Some(v1::envelope::Body::StartResponse(response)) = conflict.body else {
        panic!()
    };
    let Some(v1::start_response::Result::Failure(failure)) = response.result else {
        panic!()
    };
    assert_eq!(failure.code, v1::FailureCode::Conflict as i32);
}
fn binding(response: &v1::Envelope) -> v1::InstanceIdentity {
    let Some(v1::envelope::Body::StartResponse(v)) = &response.body else {
        panic!()
    };
    let Some(v1::start_response::Result::Success(v)) = &v.result else {
        panic!()
    };
    v.instance.clone().unwrap()
}
fn deliver(instance: v1::InstanceIdentity, n: u8, payload: &[u8]) -> v1::Envelope {
    deliver_attempt(instance, n, payload, 22)
}
fn deliver_attempt(
    instance: v1::InstanceIdentity,
    n: u8,
    payload: &[u8],
    attempt: u8,
) -> v1::Envelope {
    signed(
        v1::envelope::Body::DeliverRequest(v1::DeliverRequest {
            metadata: Some(v1::MutationMetadata {
                request: Some(metadata(n, expiry())),
            }),
            instance: Some(instance),
            message_id: id(20),
            delivery_attempt_id: id(attempt),
            operation_id: id(21),
            payload: payload.to_vec(),
            pending_correlations: vec![],
        }),
        n,
        n,
    )
}
fn acceptance(instance: v1::InstanceIdentity, n: u8) -> v1::Envelope {
    acceptance_attempt(instance, n, 22)
}
fn acceptance_attempt(instance: v1::InstanceIdentity, n: u8, attempt: u8) -> v1::Envelope {
    signed(
        v1::envelope::Body::AcceptanceRequest(v1::AcceptanceRequest {
            metadata: Some(metadata(n, expiry())),
            instance: Some(instance),
            message_id: id(20),
            delivery_attempt_id: id(attempt),
        }),
        n,
        n,
    )
}
fn observe(instance: v1::InstanceIdentity, n: u8, after_sequence: u64) -> v1::Envelope {
    signed(
        v1::envelope::Body::ObserveRequest(v1::ObserveRequest {
            metadata: Some(metadata(n, expiry())),
            instance: Some(instance),
            after_sequence,
        }),
        n,
        n,
    )
}
fn inspect(instance: v1::InstanceIdentity, n: u8) -> v1::Envelope {
    signed(
        v1::envelope::Body::InspectRequest(v1::InspectRequest {
            metadata: Some(metadata(n, expiry())),
            instance: Some(instance),
        }),
        n,
        n,
    )
}
fn acceptance_value(response: &v1::Envelope) -> v1::Acceptance {
    let Some(v1::envelope::Body::AcceptanceResponse(v)) = &response.body else {
        panic!()
    };
    let Some(v1::acceptance_response::Result::Success(v)) = &v.result else {
        panic!()
    };
    v1::Acceptance::try_from(v.acceptance).unwrap()
}

fn delivery_value(response: &v1::Envelope) -> v1::Acceptance {
    let Some(v1::envelope::Body::DeliverResponse(response)) = &response.body else {
        panic!()
    };
    let Some(v1::deliver_response::Result::Success(result)) = &response.result else {
        panic!()
    };
    v1::Acceptance::try_from(result.acceptance).unwrap()
}

#[test]
fn framing_rejects_oversized_malformed_and_truncated_without_journal_effect() {
    for bytes in [vec![0x81, 0x80, 0x10], vec![1, 0xff], vec![10, 0xff]] {
        let harness = Harness::new("none");
        let mut driver = harness.spawn();
        driver.input.as_mut().unwrap().write_all(&bytes).unwrap();
        driver.close_input();
        assert!(
            !driver
                .wait_within(Duration::from_secs(2))
                .unwrap()
                .success()
        );
        assert!(!harness.journal.exists());
    }
    let harness = Harness::new("none");
    let mut driver = harness.spawn();
    write_varint(driver.input.as_mut().unwrap(), MAX_FRAME_BYTES + 1);
    driver.close_input();
    assert!(
        !driver
            .wait_within(Duration::from_secs(2))
            .unwrap()
            .success()
    );
    assert!(!harness.journal.exists());
}

#[test]
fn authentication_binds_body_rejects_expiry_and_replay_across_restart() {
    let harness = Harness::new("none");
    let mut driver = harness.spawn();
    let original = describe(1);
    assert!(matches!(
        driver.request(&original).body,
        Some(v1::envelope::Body::DescribeResponse(_))
    ));
    let replay = driver.request(&original);
    let Some(v1::envelope::Body::DescribeResponse(v)) = replay.body else {
        panic!()
    };
    assert!(matches!(
        v.result,
        Some(v1::describe_response::Result::Failure(_))
    ));
    driver.close_input();
    assert!(
        driver
            .wait_within(Duration::from_secs(2))
            .unwrap()
            .success()
    );
    let mut restarted = harness.spawn();
    let replay = restarted.request(&original);
    let Some(v1::envelope::Body::DescribeResponse(v)) = replay.body else {
        panic!()
    };
    assert!(matches!(
        v.result,
        Some(v1::describe_response::Result::Failure(_))
    ));
    let mut mutated = start(2);
    if let Some(v1::envelope::Body::StartRequest(v)) = &mut mutated.body {
        v.trusted_configuration.push(1);
    }
    let response = restarted.request(&mutated);
    let Some(v1::envelope::Body::StartResponse(v)) = response.body else {
        panic!()
    };
    assert!(matches!(
        v.result,
        Some(v1::start_response::Result::Failure(_))
    ));
    let mut expired = describe(3);
    let meta = match expired.body.as_mut().unwrap() {
        v1::envelope::Body::DescribeRequest(v) => v.metadata.as_mut().unwrap(),
        _ => unreachable!(),
    };
    meta.authentication.as_mut().unwrap().expires_unix_ms = 1;
    sign_envelope(&mut expired, SECRET).unwrap();
    let response = restarted.request(&expired);
    let Some(v1::envelope::Body::DescribeResponse(v)) = response.body else {
        panic!()
    };
    assert!(matches!(
        v.result,
        Some(v1::describe_response::Result::Failure(_))
    ));
}

#[test]
fn acceptance_windows_and_external_effects_survive_restart_exactly() {
    for (fault, expected, effects) in [
        ("crash_before_acceptance", v1::Acceptance::NotAccepted, 0),
        ("crash_after_volatile_receipt", v1::Acceptance::Unknown, 1),
        (
            "crash_after_durable_acceptance",
            v1::Acceptance::Accepted,
            1,
        ),
    ] {
        let harness = Harness::new(fault);
        let mut driver = harness.spawn();
        let instance = binding(&driver.request(&start(10)));
        driver.send(&deliver(instance.clone(), 11, b"payload"));
        let status = driver.wait_within(Duration::from_secs(2)).unwrap();
        assert_eq!(status.code(), Some(EXIT_CRASH));
        harness.scenario("none");
        let mut restarted = harness.spawn();
        assert_eq!(
            acceptance_value(&restarted.request(&acceptance(instance, 12))),
            expected
        );
        assert_eq!(harness.effects().len(), effects);
    }
}

#[test]
fn journal_commit_boundaries_never_invent_acceptance() {
    for (fault, expected, effects, intent_committed) in [
        (
            "before_intent_temp_write",
            v1::Acceptance::NotAccepted,
            0,
            false,
        ),
        (
            "after_intent_temp_write",
            v1::Acceptance::NotAccepted,
            0,
            false,
        ),
        (
            "after_intent_temp_fsync",
            v1::Acceptance::NotAccepted,
            0,
            false,
        ),
        ("after_intent_rename", v1::Acceptance::Unknown, 0, true),
        (
            "after_intent_parent_fsync",
            v1::Acceptance::Unknown,
            0,
            true,
        ),
        ("before_temp_write", v1::Acceptance::Unknown, 1, true),
        ("after_temp_write", v1::Acceptance::Unknown, 1, true),
        ("after_temp_fsync", v1::Acceptance::Unknown, 1, true),
        ("after_rename", v1::Acceptance::Accepted, 1, true),
        ("after_parent_fsync", v1::Acceptance::Accepted, 1, true),
    ] {
        let harness = Harness::new("none");
        harness.journal_fault(fault);
        let mut driver = harness.spawn();
        let instance = binding(&driver.request(&start(30)));
        driver.send(&deliver(instance.clone(), 31, b"journal-boundary"));
        assert!(
            !driver
                .wait_within(Duration::from_secs(2))
                .unwrap()
                .success()
        );

        harness.scenario("none");
        let mut restarted = harness.spawn();
        assert_eq!(
            acceptance_value(&restarted.request(&acceptance(instance.clone(), 32))),
            expected,
            "unexpected reconciliation at {fault}"
        );
        assert_eq!(harness.effects().len(), effects, "effect count at {fault}");
        if intent_committed {
            let replay = restarted.request(&deliver(instance.clone(), 33, b"journal-boundary"));
            assert_eq!(delivery_value(&replay), expected);
            assert!(harness.effects().len() <= 1, "reinjection at {fault}");
            let conflict = restarted.request(&deliver(instance, 34, b"different-boundary"));
            let Some(v1::envelope::Body::DeliverResponse(conflict)) = conflict.body else {
                panic!()
            };
            assert!(matches!(
                conflict.result,
                Some(v1::deliver_response::Result::Failure(_))
            ));
            assert!(
                harness.effects().len() <= 1,
                "conflicting reinjection at {fault}"
            );
        }
    }
}

#[test]
fn duplicate_is_not_reinjected_and_conflicting_payload_fails() {
    let harness = Harness::new("none");
    let mut driver = harness.spawn();
    let instance = binding(&driver.request(&start(20)));
    let first = deliver(instance.clone(), 21, b"same");
    let _ = driver.request(&first);
    let _ = driver.request(&deliver(instance.clone(), 22, b"same"));
    assert_eq!(harness.effects().len(), 1);
    let conflict = driver.request(&deliver(instance, 23, b"different"));
    let Some(v1::envelope::Body::DeliverResponse(v)) = conflict.body else {
        panic!()
    };
    assert!(matches!(
        v.result,
        Some(v1::deliver_response::Result::Failure(_))
    ));
    assert_eq!(harness.effects().len(), 1);
}

#[test]
fn changed_attempt_cannot_blindly_reinject_or_claim_prior_acceptance() {
    let harness = Harness::new("none");
    let mut driver = harness.spawn();
    let instance = binding(&driver.request(&start(70)));
    assert_eq!(
        delivery_value(&driver.request(&deliver_attempt(instance.clone(), 71, b"payload", 22,))),
        v1::Acceptance::Accepted
    );

    for response in [
        driver.request(&deliver_attempt(instance.clone(), 72, b"payload", 23)),
        driver.request(&acceptance_attempt(instance, 73, 23)),
    ] {
        match response.body.unwrap() {
            v1::envelope::Body::DeliverResponse(value) => assert!(matches!(
                value.result,
                Some(v1::deliver_response::Result::Failure(_))
            )),
            v1::envelope::Body::AcceptanceResponse(value) => assert!(matches!(
                value.result,
                Some(v1::acceptance_response::Result::Failure(_))
            )),
            _ => panic!(),
        }
    }
    assert_eq!(harness.effects().len(), 1);
}

#[test]
fn stdin_eof_is_bounded_ownership_loss_exit() {
    let harness = Harness::new("none");
    let mut driver = harness.spawn();
    let _ = driver.request(&describe(30));
    driver.close_input();
    assert!(driver.wait_within(Duration::from_secs(1)).is_some());
}

#[test]
fn subprocess_reports_are_correlated_to_the_exact_durable_delivery() {
    let harness = Harness::new("none");
    harness.scenario_json(
        r#"{"events":[
          {"kind":"progress","operation_id":"15151515-1515-1515-1515-151515151515","message_id":"14141414-1414-1414-1414-141414141414","payload":"working"},
          {"kind":"outcome","operation_id":"15151515-1515-1515-1515-151515151515","message_id":"14141414-1414-1414-1414-141414141414","outcome":"succeeded"}
        ]}"#,
    );
    let mut driver = harness.spawn();
    let instance = binding(&driver.request(&start(40)));
    let delivery = driver.request(&deliver(instance.clone(), 41, b"work"));
    assert_eq!(delivery_value(&delivery), v1::Acceptance::Accepted);
    let mut guard =
        navigator_driver_protocol::OperationReportGuard::new(id(21), id(20), instance.clone())
            .unwrap();
    for (nonce, expected) in [
        (42, navigator_driver_protocol::SettlementAction::Continue),
        (
            43,
            navigator_driver_protocol::SettlementAction::Terminal(v1::ReportKind::Succeeded),
        ),
    ] {
        let response = driver.request(&observe(instance.clone(), nonce, u64::from(nonce - 42)));
        let Some(v1::envelope::Body::Event(event)) = response.body else {
            panic!("real process did not return a DriverEvent")
        };
        assert_eq!(guard.observe(&event), Ok(expected));
    }
    assert_eq!(harness.effects().len(), 1);
}

#[test]
fn unacknowledged_observe_event_redelivers_exactly_in_process_and_after_restart() {
    let harness = Harness::new("none");
    harness.scenario_json(
        r#"{"events":[{"kind":"progress","operation_id":"15151515-1515-1515-1515-151515151515","message_id":"14141414-1414-1414-1414-141414141414","payload":"working"}]}"#,
    );
    let mut first = harness.spawn();
    let instance = binding(&first.request(&start(60)));
    assert_eq!(
        delivery_value(&first.request(&deliver(instance.clone(), 64, b"work"))),
        v1::Acceptance::Accepted
    );
    let normalize = |envelope: v1::Envelope| {
        let Some(v1::envelope::Body::Event(mut event)) = envelope.body else {
            panic!("event")
        };
        event.in_reply_to.clear();
        event
    };
    let observed = normalize(first.request(&observe(instance.clone(), 61, 0)));
    let replayed = normalize(first.request(&observe(instance.clone(), 62, 0)));
    assert_eq!(observed, replayed, "read advanced the durable event cursor");
    first.close_input();
    assert!(first.wait_within(Duration::from_secs(1)).is_some());

    let mut restarted = harness.spawn();
    let after_restart = normalize(restarted.request(&observe(instance, 63, 0)));
    assert_eq!(
        observed, after_restart,
        "restart changed an unacknowledged event"
    );
}

#[test]
fn subprocess_idle_without_report_reaches_reminder_then_deadline_not_success() {
    let harness = Harness::new("none");
    let mut driver = harness.spawn();
    let instance = binding(&driver.request(&start(50)));
    assert_eq!(
        delivery_value(&driver.request(&deliver(instance.clone(), 51, b"work"))),
        v1::Acceptance::Accepted
    );
    let response = driver.request(&inspect(instance.clone(), 52));
    let Some(v1::envelope::Body::InspectResponse(response)) = response.body else {
        panic!("real process did not return inspect state")
    };
    let Some(v1::inspect_response::Result::Success(result)) = response.result else {
        panic!("real process did not return inspect success")
    };
    assert_eq!(
        v1::InstanceState::try_from(result.state).unwrap(),
        v1::InstanceState::Idle
    );
    let mut guard =
        navigator_driver_protocol::OperationReportGuard::new(id(21), id(20), instance).unwrap();
    assert_eq!(
        guard.settled_without_report(),
        navigator_driver_protocol::SettlementAction::Remind
    );
    assert_eq!(
        guard.settled_without_report(),
        navigator_driver_protocol::SettlementAction::Deadline
    );
}

#[test]
fn invalid_script_cannot_become_a_shared_test_oracle() {
    for scenario in [
        r#"{"inspect_states":["success"]}"#,
        r#"{"events":[{"kind":"outcome","operation_id":"not-an-id","message_id":"14141414-1414-1414-1414-141414141414","outcome":"succeeded"}]}"#,
        r#"{"events":[{"kind":"outcome","operation_id":"15151515-1515-1515-1515-151515151515","message_id":"14141414-1414-1414-1414-141414141414","outcome":"typo-success"}]}"#,
    ] {
        let harness = Harness::new("none");
        harness.scenario_json(scenario);
        let mut driver = harness.spawn();
        driver.close_input();
        assert!(
            !driver
                .wait_within(Duration::from_secs(1))
                .unwrap()
                .success()
        );
        assert!(!harness.journal.exists());
        assert!(harness.effects().is_empty());
    }
}

fn u128_id(bytes: &[u8]) -> u128 {
    u128::from_be_bytes(bytes.try_into().unwrap())
}
fn wire_id(value: u128) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}
fn observed(v: &v1::InstanceIdentity) -> InstanceBinding {
    InstanceBinding {
        driver: u128_id(&v.driver_id),
        session: u128_id(&v.session_id),
        participant: u128_id(&v.participant_id),
        launch_attempt: u128_id(&v.launch_attempt_id),
        instance: u128_id(&v.instance_id),
        ownership_epoch: v.ownership_epoch,
    }
}
fn wire(v: InstanceBinding) -> v1::InstanceIdentity {
    v1::InstanceIdentity {
        driver_id: wire_id(v.driver),
        session_id: wire_id(v.session),
        participant_id: wire_id(v.participant),
        launch_attempt_id: wire_id(v.launch_attempt),
        instance_id: wire_id(v.instance),
        ownership_epoch: v.ownership_epoch,
    }
}
fn map_acceptance(value: i32) -> AcceptanceObservation {
    match v1::Acceptance::try_from(value).unwrap() {
        v1::Acceptance::Accepted => AcceptanceObservation::Accepted,
        v1::Acceptance::NotAccepted => AcceptanceObservation::NotAccepted,
        _ => AcceptanceObservation::Unknown,
    }
}

impl Subject<'_> {
    fn call(&mut self, body: v1::envelope::Body) -> v1::Envelope {
        self.nonce = self.nonce.wrapping_add(1);
        self.driver.request(&signed(body, self.nonce, self.nonce))
    }
}
impl DriverSubject for Subject<'_> {
    async fn describe(&mut self) -> Result<DriverDescription, DriverErrorKind> {
        let r = self.call(v1::envelope::Body::DescribeRequest(v1::DescribeRequest {
            metadata: Some(metadata(1, expiry())),
        }));
        let Some(v1::envelope::Body::DescribeResponse(v)) = r.body else {
            return Err(DriverErrorKind::Unavailable);
        };
        let Some(v1::describe_response::Result::Success(v)) = v.result else {
            return Err(DriverErrorKind::Authentication);
        };
        let p = v.protocol.unwrap();
        Ok(DriverDescription {
            protocol_minimum: p.minimum,
            protocol_maximum: p.maximum,
            capabilities: v
                .capabilities
                .into_iter()
                .map(|c| CapabilityObservation {
                    id: c.id,
                    version: c.version,
                })
                .collect(),
        })
    }
    async fn start(
        &mut self,
        participant: u128,
        launch_attempt: u128,
        session: u128,
        ownership_epoch: u64,
        required: Vec<CapabilityObservation>,
    ) -> Result<InstanceBinding, DriverErrorKind> {
        let mut m = metadata(1, expiry());
        m.required_capabilities = required
            .into_iter()
            .map(|c| v1::CapabilityRequirement {
                id: c.id,
                minimum_version: c.version,
                parameters: vec![],
            })
            .collect();
        let r = self.call(v1::envelope::Body::StartRequest(v1::StartRequest {
            metadata: Some(v1::MutationMetadata { request: Some(m) }),
            participant_id: wire_id(participant),
            launch_attempt_id: wire_id(launch_attempt),
            instance_id: wire_id(launch_attempt.wrapping_add(1)),
            trusted_configuration: vec![],
            session_id: wire_id(session),
            ownership_epoch,
        }));
        let Some(v1::envelope::Body::StartResponse(v)) = r.body else {
            return Err(DriverErrorKind::Unavailable);
        };
        let Some(v1::start_response::Result::Success(v)) = v.result else {
            return Err(DriverErrorKind::Unsupported);
        };
        Ok(observed(&v.instance.unwrap()))
    }
    async fn inspect(
        &mut self,
        i: InstanceBinding,
    ) -> Result<InstanceObservation, DriverErrorKind> {
        if self.stopped || self.driver.input.is_none() {
            return Err(DriverErrorKind::Unavailable);
        }
        if self
            .driver
            .child
            .try_wait()
            .map_err(|_| DriverErrorKind::Unavailable)?
            .is_some()
        {
            return Err(DriverErrorKind::Unavailable);
        }
        let r = self.call(v1::envelope::Body::InspectRequest(v1::InspectRequest {
            metadata: Some(metadata(1, expiry())),
            instance: Some(wire(i)),
        }));
        let Some(v1::envelope::Body::InspectResponse(v)) = r.body else {
            return Err(DriverErrorKind::Unavailable);
        };
        let Some(v1::inspect_response::Result::Success(v)) = v.result else {
            return Err(DriverErrorKind::Conflict);
        };
        Ok(match v1::InstanceState::try_from(v.state).unwrap() {
            v1::InstanceState::Ready => InstanceObservation::Ready,
            v1::InstanceState::Idle => InstanceObservation::Idle,
            v1::InstanceState::Stopped => InstanceObservation::Stopped,
            _ => InstanceObservation::Uncertain,
        })
    }
    async fn deliver(
        &mut self,
        i: InstanceBinding,
        message: u128,
        operation: u128,
        payload: Vec<u8>,
    ) -> Result<AcceptanceObservation, DriverErrorKind> {
        let r = self.call(v1::envelope::Body::DeliverRequest(v1::DeliverRequest {
            metadata: Some(v1::MutationMetadata {
                request: Some(metadata(1, expiry())),
            }),
            instance: Some(wire(i)),
            message_id: wire_id(message),
            delivery_attempt_id: wire_id(message),
            operation_id: wire_id(operation),
            payload,
            pending_correlations: vec![],
        }));
        let Some(v1::envelope::Body::DeliverResponse(v)) = r.body else {
            return Err(DriverErrorKind::Unavailable);
        };
        let Some(v1::deliver_response::Result::Success(v)) = v.result else {
            return Err(DriverErrorKind::Conflict);
        };
        Ok(map_acceptance(v.acceptance))
    }
    async fn acceptance(
        &mut self,
        i: InstanceBinding,
        message: u128,
    ) -> Result<AcceptanceObservation, DriverErrorKind> {
        let r = self.call(v1::envelope::Body::AcceptanceRequest(
            v1::AcceptanceRequest {
                metadata: Some(metadata(1, expiry())),
                instance: Some(wire(i)),
                message_id: wire_id(message),
                delivery_attempt_id: wire_id(message),
            },
        ));
        let Some(v1::envelope::Body::AcceptanceResponse(v)) = r.body else {
            return Err(DriverErrorKind::Unavailable);
        };
        let Some(v1::acceptance_response::Result::Success(v)) = v.result else {
            return Err(DriverErrorKind::Conflict);
        };
        Ok(map_acceptance(v.acceptance))
    }
    async fn cancel(&mut self, i: InstanceBinding, operation: u128) -> Result<(), DriverErrorKind> {
        let r = self.call(v1::envelope::Body::CancelRequest(v1::CancelRequest {
            metadata: Some(v1::MutationMetadata {
                request: Some(metadata(1, expiry())),
            }),
            instance: Some(wire(i)),
            operation_id: wire_id(operation),
        }));
        matches!(r.body, Some(v1::envelope::Body::CancelResponse(_)))
            .then_some(())
            .ok_or(DriverErrorKind::Unavailable)
    }
    async fn stop(&mut self, i: InstanceBinding) -> Result<StopObservation, DriverErrorKind> {
        let r = self.call(v1::envelope::Body::StopRequest(v1::StopRequest {
            metadata: Some(v1::MutationMetadata {
                request: Some(metadata(1, expiry())),
            }),
            instance: Some(wire(i)),
        }));
        let Some(v1::envelope::Body::StopResponse(v)) = r.body else {
            return Err(DriverErrorKind::Unavailable);
        };
        let Some(v1::stop_response::Result::Success(v)) = v.result else {
            return Err(DriverErrorKind::Conflict);
        };
        let observation = match v1::StopDisposition::try_from(v.disposition).unwrap() {
            v1::StopDisposition::StoppedConfirmed => StopObservation::Confirmed,
            v1::StopDisposition::AlreadyStopped => StopObservation::AlreadyStopped,
            v1::StopDisposition::StopCleanupRequired => StopObservation::CleanupRequired,
            _ => StopObservation::Uncertain,
        };
        if matches!(observation, StopObservation::Confirmed) {
            self.driver = self.harness.spawn();
        }
        self.stopped = matches!(observation, StopObservation::AlreadyStopped);
        Ok(observation)
    }
    async fn native_delivery_count(&mut self) -> Result<u64, DriverErrorKind> {
        Ok(self.harness.effects().len() as u64)
    }
    async fn native_cancel_count(&mut self) -> Result<u64, DriverErrorKind> {
        let v: serde_json::Value = serde_json::from_slice(
            &fs::read(&self.harness.journal).map_err(|_| DriverErrorKind::Unavailable)?,
        )
        .map_err(|_| DriverErrorKind::Unavailable)?;
        v["cancel_count"]
            .as_u64()
            .ok_or(DriverErrorKind::Unavailable)
    }
}

#[tokio::test]
async fn reusable_base_contract_runs_against_subprocess() {
    let h = Harness::new("none");
    let mut s = Subject {
        driver: h.spawn(),
        harness: &h,
        nonce: 40,
        stopped: false,
    };
    assert_driver_contract(&mut s).await.unwrap();
}
#[tokio::test]
async fn reusable_durable_contract_runs_against_subprocess() {
    let h = Harness::new("none");
    let mut s = Subject {
        driver: h.spawn(),
        harness: &h,
        nonce: 80,
        stopped: false,
    };
    assert_durable_acceptance_contract(&mut s).await.unwrap();
}

#[test]
fn frozen_v1_start_fixture_crosses_the_real_driver_process() {
    let harness = Harness::new("none");
    harness.scenario_json(
        r#"{"events":[{"kind":"outcome","operation_id":"15151515-1515-1515-1515-151515151515","message_id":"14141414-1414-1414-1414-141414141414","outcome":"succeeded"}]}"#,
    );
    let mut driver = harness.spawn();
    let mut request = v1::Envelope::decode(
        include_bytes!("../../navigator-driver-protocol/fixtures/start-v1.bin").as_slice(),
    )
    .unwrap();
    let Some(v1::envelope::Body::StartRequest(start)) = request.body.as_mut() else {
        panic!("frozen v1 fixture is not Start")
    };
    *start.metadata.as_mut().unwrap().request.as_mut().unwrap() = metadata(91, expiry());
    sign_envelope(&mut request, SECRET).unwrap();
    let response = driver.request(&request);
    assert_eq!(response.response_to_request_id, id(171));
    let instance = binding(&response);
    assert_eq!(
        delivery_value(&driver.request(&deliver(instance.clone(), 92, b"old-client-work"))),
        v1::Acceptance::Accepted
    );
    let first = driver.request(&observe(instance.clone(), 93, 0));
    let replay = driver.request(&observe(instance.clone(), 94, 0));
    let report = |envelope: v1::Envelope| {
        let Some(v1::envelope::Body::Event(event)) = envelope.body else {
            panic!("old Driver did not report")
        };
        event
    };
    let first = report(first);
    let replay = report(replay);
    let mut normalized_first = first.clone();
    let mut normalized_replay = replay;
    normalized_first.in_reply_to.clear();
    normalized_replay.in_reply_to.clear();
    assert_eq!(
        normalized_first, normalized_replay,
        "unacked old report did not replay exactly"
    );
    let mut guard =
        navigator_driver_protocol::OperationReportGuard::new(id(21), id(20), instance).unwrap();
    assert_eq!(
        guard.observe(&first),
        Ok(navigator_driver_protocol::SettlementAction::Terminal(
            v1::ReportKind::Succeeded
        ))
    );
    let journal = fs::read_to_string(&harness.journal).unwrap();
    assert!(
        journal.contains("accepted"),
        "old Start journal missing: {journal}"
    );
}
