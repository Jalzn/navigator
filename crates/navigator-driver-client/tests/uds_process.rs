#![cfg(unix)]

use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    os::unix::net::{UnixListener, UnixStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use navigator_driver_client::{ClientError, DriverClient, DriverCredential};
use navigator_driver_fake::{read_frame, write_frame};
use navigator_driver_protocol::v1;
use prost::Message;
use tempfile::TempDir;

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
const CONTROL_SOCKET_ENV: &str = "NAVIGATOR_FAKE_DRIVER_CONTROL_SOCKET";
const CREDENTIAL_FILE_ENV: &str = "NAVIGATOR_FAKE_DRIVER_CREDENTIAL_FILE";
const JOURNAL_FILE_ENV: &str = "NAVIGATOR_FAKE_DRIVER_JOURNAL_FILE";
const SCENARIO_FILE_ENV: &str = "NAVIGATOR_FAKE_DRIVER_SCENARIO_FILE";

struct Harness {
    _dir: TempDir,
    socket: std::path::PathBuf,
    journal: std::path::PathBuf,
    child: Child,
}

impl Harness {
    fn spawn(scenario: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let scenario_path = dir.path().join("scenario.json");
        let journal = dir.path().join("journal.json");
        let credential = dir.path().join("credential");
        let socket = dir.path().join("control.sock");
        fs::write(&scenario_path, scenario).unwrap();
        fs::write(&credential, SECRET).unwrap();
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).unwrap();
        let child = Command::new(std::env::var("CARGO_BIN_EXE_navigator-driver-fake").unwrap())
            .env(SCENARIO_FILE_ENV, scenario_path)
            .env(JOURNAL_FILE_ENV, &journal)
            .env(CREDENTIAL_FILE_ENV, credential)
            .env(CONTROL_SOCKET_ENV, &socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !socket.exists() {
            assert!(
                Instant::now() < deadline,
                "fake did not create control socket"
            );
            thread::sleep(Duration::from_millis(10));
        }
        Self {
            _dir: dir,
            socket,
            journal,
            child,
        }
    }

    fn client(&self, secret: &[u8]) -> DriverClient {
        DriverClient::connect(
            &self.socket,
            DriverCredential::new(secret.to_vec()).unwrap(),
            Duration::from_secs(2),
        )
        .unwrap()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn id(value: u8) -> Vec<u8> {
    vec![value; 16]
}

#[test]
#[cfg(feature = "uds-process-tests")]
fn real_control_uses_uds_and_stdin_eof_only_revokes_ownership() {
    let scenario = r#"{"events":[{"kind":"outcome","operation_id":"15151515-1515-1515-1515-151515151515","message_id":"14141414-1414-1414-1414-141414141414","outcome":"succeeded"}]}"#;
    let mut harness = Harness::spawn(scenario);
    let mut client = harness.client(SECRET);
    assert!(!client.describe().unwrap().implementation.is_empty());
    assert_eq!(
        fs::symlink_metadata(&harness.socket)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let started = client
        .start(id(10), id(2), id(3), id(5), id(4), 7, Vec::new())
        .unwrap();
    let instance = started.instance.unwrap();
    assert_eq!(instance.instance_id, id(5));
    assert_eq!(
        client
            .deliver(id(11), instance.clone(), id(20), id(21), b"work".to_vec())
            .unwrap(),
        v1::Acceptance::Accepted
    );
    let reminder = client
        .reminder(instance.clone(), id(12), id(21), id(20))
        .unwrap();
    assert_eq!(
        reminder.disposition,
        v1::RemindDisposition::ReminderRequested as i32
    );
    assert!(
        fs::read_to_string(&harness.journal)
            .unwrap()
            .contains("\"reminder_count\":1")
    );
    let event = client.observe(instance.clone(), 0).unwrap();
    assert!(matches!(
        event.event,
        Some(v1::driver_event::Event::Report(_))
    ));
    drop(client);
    let mut reconnected = harness.client(SECRET);
    assert!(!reconnected.describe().unwrap().implementation.is_empty());
    assert_eq!(
        reconnected
            .deliver(id(11), instance, id(20), id(21), b"work".to_vec())
            .unwrap(),
        v1::Acceptance::Accepted
    );
    drop(reconnected);
    assert!(harness.child.try_wait().unwrap().is_none());
    drop(harness.child.stdin.take());
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if harness.child.try_wait().unwrap().is_some() {
            break;
        }
        assert!(Instant::now() < deadline, "stdin EOF did not stop fake");
        thread::sleep(Duration::from_millis(10));
    }
    assert!(!harness.socket.exists());
}

#[test]
#[cfg(feature = "uds-process-tests")]
fn wrong_authentication_fails_without_a_test_bypass() {
    let harness = Harness::spawn("{}");
    let mut client = harness.client(b"wrong-secret-wrong-secret-12345678");
    assert!(client.describe().is_err(), "wrong credential was accepted");
    assert!(
        !harness.journal.exists(),
        "wrong key produced a durable effect"
    );
    drop(client);
    assert!(
        !harness
            .client(SECRET)
            .describe()
            .unwrap()
            .implementation
            .is_empty(),
        "rejected authentication poisoned the valid listener"
    );
}

#[test]
#[cfg(feature = "uds-process-tests")]
fn client_rejects_public_socket_permissions_before_sending_authentication() {
    let harness = Harness::spawn("{}");
    fs::set_permissions(&harness.socket, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(matches!(
        DriverClient::connect(
            &harness.socket,
            DriverCredential::new(SECRET.to_vec()).unwrap(),
            Duration::from_secs(1),
        ),
        Err(ClientError::Protocol)
    ));
    fs::set_permissions(&harness.socket, fs::Permissions::from_mode(0o600)).unwrap();
    let mut client = harness.client(SECRET);
    assert!(!client.describe().unwrap().implementation.is_empty());
}

#[test]
#[cfg(feature = "uds-process-tests")]
fn oversized_control_frame_is_isolated_and_owner_can_reconnect() {
    let harness = Harness::spawn("{}");
    let mut raw = UnixStream::connect(&harness.socket).unwrap();
    raw.write_all(&[0x81, 0x80, 0x10]).unwrap();
    drop(raw);
    thread::sleep(Duration::from_millis(30));
    let mut client = harness.client(SECRET);
    assert!(!client.describe().unwrap().implementation.is_empty());
}

#[test]
#[cfg(feature = "uds-process-tests")]
fn ownership_eof_interrupts_hung_driver_and_cleans_socket() {
    let mut harness = Harness::spawn(r#"{"delivery_fault":"hang"}"#);
    let mut client = harness.client(SECRET);
    let started = client
        .start(id(30), id(2), id(3), id(5), id(4), 7, Vec::new())
        .unwrap();
    let instance = started.instance.unwrap();
    let blocked =
        thread::spawn(move || client.deliver(id(31), instance, id(20), id(21), b"hang".to_vec()));
    thread::sleep(Duration::from_millis(50));
    drop(harness.child.stdin.take());
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if harness.child.try_wait().unwrap().is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "ownership EOF did not interrupt hang"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(!harness.socket.exists());
    assert!(blocked.join().unwrap().is_err());
}

#[test]
#[cfg(feature = "uds-process-tests")]
fn partial_frame_client_is_bounded_and_does_not_starve_reconnection() {
    let harness = Harness::spawn("{}");
    let mut stalled = UnixStream::connect(&harness.socket).unwrap();
    stalled
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stalled.write_all(&[0x80]).unwrap();
    let mut byte = [0_u8; 1];
    let closed = stalled.read(&mut byte);
    assert!(
        matches!(closed, Err(_) | Ok(0)),
        "partial frame connection was not evicted within the control bound"
    );
    let mut owner = harness.client(SECRET);
    assert!(!owner.describe().unwrap().implementation.is_empty());
}

#[test]
#[cfg(feature = "uds-process-tests")]
fn credential_symlink_and_public_credential_file_fail_before_socket_creation() {
    use std::os::unix::fs::symlink;

    for public_file in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let scenario = directory.path().join("scenario.json");
        let journal = directory.path().join("journal.json");
        let credential_target = directory.path().join("credential-target");
        let credential = directory.path().join("credential");
        let socket = directory.path().join("control.sock");
        fs::write(&scenario, "{}").unwrap();
        fs::write(&credential_target, SECRET).unwrap();
        fs::set_permissions(
            &credential_target,
            fs::Permissions::from_mode(if public_file { 0o644 } else { 0o600 }),
        )
        .unwrap();
        if public_file {
            fs::rename(&credential_target, &credential).unwrap();
        } else {
            symlink(&credential_target, &credential).unwrap();
        }
        let status = Command::new(std::env::var("CARGO_BIN_EXE_navigator-driver-fake").unwrap())
            .env(SCENARIO_FILE_ENV, &scenario)
            .env(JOURNAL_FILE_ENV, &journal)
            .env(CREDENTIAL_FILE_ENV, &credential)
            .env(CONTROL_SOCKET_ENV, &socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success());
        assert!(
            !socket.exists(),
            "unsafe credential reached socket creation"
        );
    }
}

#[test]
#[cfg(feature = "uds-process-tests")]
fn prebound_or_replacement_socket_cannot_forge_an_authenticated_driver() {
    let harness = Harness::spawn("{}");
    let mut established = harness.client(SECRET);
    assert!(!established.describe().unwrap().implementation.is_empty());

    fs::remove_file(&harness.socket).unwrap();
    let listener = UnixListener::bind(&harness.socket).unwrap();
    fs::set_permissions(&harness.socket, fs::Permissions::from_mode(0o600)).unwrap();
    let attacker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_frame(&mut stream).unwrap().unwrap();
        let request = v1::Envelope::decode(request.as_slice()).unwrap();
        let request_id = match request.body.as_ref().unwrap() {
            v1::envelope::Body::DescribeRequest(value) => {
                value.metadata.as_ref().unwrap().request_id.clone()
            }
            _ => panic!("unexpected request"),
        };
        let response = v1::Envelope {
            envelope_id: id(99),
            response_authenticator: vec![0; 32],
            response_to_request_id: request_id,
            body: Some(v1::envelope::Body::DescribeResponse(v1::DescribeResponse {
                in_reply_to: request.envelope_id,
                result: Some(v1::describe_response::Result::Success(v1::DescribeResult {
                    driver_id: id(98),
                    implementation: "forged".into(),
                    implementation_version: "1".into(),
                    protocol: Some(v1::ProtocolRange {
                        minimum: 1,
                        maximum: 1,
                    }),
                    capabilities: Vec::new(),
                })),
            })),
        };
        write_frame(&mut stream, &response).unwrap();
    });
    let mut replacement = harness.client(SECRET);
    assert!(
        replacement.describe().is_err(),
        "forged response was accepted"
    );
    attacker.join().unwrap();
    assert!(
        !established.describe().unwrap().implementation.is_empty(),
        "replacing the pathname hijacked an established authenticated stream"
    );
}
