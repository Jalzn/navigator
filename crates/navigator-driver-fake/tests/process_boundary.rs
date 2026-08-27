use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use navigator_driver_fake::{
    CREDENTIAL_FILE_ENV, JOURNAL_FILE_ENV, SCENARIO_FILE_ENV, credential_key_id, read_frame,
    sign_envelope, write_frame,
};
use navigator_driver_protocol::{Validate, decode_envelope, v1};
use tempfile::TempDir;

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

struct DriverProcess {
    child: Child,
    input: Option<ChildStdin>,
    output: ChildStdout,
}

impl DriverProcess {
    fn spawn(directory: &TempDir) -> Self {
        let credential = directory.path().join("credential");
        if !credential.exists() {
            fs::write(&credential, SECRET).expect("credential");
            fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).expect("mode");
            fs::write(
                directory.path().join("scenario.json"),
                br#"{"capabilities":["durable.acceptance"],"inspect_states":["ready"]}"#,
            )
            .expect("scenario");
        }
        let mut child = Command::new(env!("CARGO_BIN_EXE_navigator-driver-fake"))
            .env(CREDENTIAL_FILE_ENV, credential)
            .env(SCENARIO_FILE_ENV, directory.path().join("scenario.json"))
            .env(JOURNAL_FILE_ENV, directory.path().join("journal.json"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn fake Driver");
        let input = child.stdin.take().expect("stdin");
        let output = child.stdout.take().expect("stdout");
        Self {
            child,
            input: Some(input),
            output,
        }
    }

    fn exchange(&mut self, request: &v1::Envelope) -> v1::Envelope {
        write_frame(self.input.as_mut().expect("connected"), request).expect("write request");
        let bytes = read_frame(&mut self.output)
            .expect("read response")
            .expect("response before EOF");
        let response = decode_envelope(&bytes).expect("decode response");
        response.validate().expect("fake emitted valid response");
        response
    }

    fn disconnect_owner(&mut self) {
        drop(self.input.take());
    }

    fn exits_within(&mut self, bound: Duration) -> bool {
        let deadline = Instant::now() + bound;
        loop {
            if self.child.try_wait().expect("wait").is_some() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::yield_now();
        }
    }
}

impl Drop for DriverProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn signed_describe(secret: &[u8], nonce: u128, expires: i64) -> v1::Envelope {
    let id = |value: u128| value.to_be_bytes().to_vec();
    let mut envelope = v1::Envelope {
        envelope_id: id(nonce.wrapping_add(100)),
        response_authenticator: Vec::new(),
        response_to_request_id: Vec::new(),
        body: Some(v1::envelope::Body::DescribeRequest(v1::DescribeRequest {
            metadata: Some(v1::RequestMetadata {
                protocol_version: 1,
                authentication: Some(v1::Authentication {
                    key_id: credential_key_id(secret).to_vec(),
                    nonce: id(nonce),
                    expires_unix_ms: expires,
                    authenticator: vec![0; 32],
                    request_digest: vec![0; 32],
                }),
                required_capabilities: Vec::new(),
                request_id: id(nonce.wrapping_add(200)),
            }),
        })),
    };
    sign_envelope(&mut envelope, secret).expect("sign");
    envelope
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis()
        .try_into()
        .expect("time fits")
}

fn failure_code(response: &v1::Envelope) -> Option<v1::FailureCode> {
    let v1::envelope::Body::DescribeResponse(response) = response.body.as_ref()? else {
        return None;
    };
    let v1::describe_response::Result::Failure(failure) = response.result.as_ref()? else {
        return None;
    };
    v1::FailureCode::try_from(failure.code).ok()
}

#[test]
fn authentication_replay_is_rejected_across_process_restart() {
    let directory = TempDir::new().expect("tempdir");
    let secret = SECRET;
    let request = signed_describe(secret, 1, now_ms() + 60_000);
    let mut first = DriverProcess::spawn(&directory);
    assert!(matches!(
        first.exchange(&request).body,
        Some(v1::envelope::Body::DescribeResponse(v1::DescribeResponse {
            result: Some(v1::describe_response::Result::Success(_)),
            ..
        }))
    ));
    assert_eq!(
        failure_code(&first.exchange(&request)),
        Some(v1::FailureCode::Authentication)
    );
    first.disconnect_owner();
    assert!(first.exits_within(Duration::from_secs(1)));

    let mut restarted = DriverProcess::spawn(&directory);
    assert_eq!(
        failure_code(&restarted.exchange(&request)),
        Some(v1::FailureCode::Authentication)
    );
}

#[test]
fn expired_authentication_has_no_persistent_effect_and_eof_revokes_ownership() {
    let directory = TempDir::new().expect("tempdir");
    let mut process = DriverProcess::spawn(&directory);
    let expired = signed_describe(SECRET, 2, now_ms());
    assert_eq!(
        failure_code(&process.exchange(&expired)),
        Some(v1::FailureCode::Authentication)
    );
    process.disconnect_owner();
    assert!(process.exits_within(Duration::from_secs(1)));
}
