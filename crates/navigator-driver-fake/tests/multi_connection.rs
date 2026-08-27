#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use navigator_driver_client::{DriverClient, DriverCredential};
use tempfile::TempDir;

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

struct Harness {
    _directory: TempDir,
    socket: std::path::PathBuf,
    child: Child,
}

impl Harness {
    fn spawn() -> Self {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let scenario = directory.path().join("scenario.json");
        let journal = directory.path().join("journal.json");
        let credential = directory.path().join("credential");
        let socket = directory.path().join("control.sock");
        fs::write(&scenario, "{}").unwrap();
        fs::write(&credential, SECRET).unwrap();
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_navigator-driver-fake"))
            .env("NAVIGATOR_FAKE_DRIVER_SCENARIO_FILE", scenario)
            .env("NAVIGATOR_FAKE_DRIVER_JOURNAL_FILE", journal)
            .env("NAVIGATOR_FAKE_DRIVER_CREDENTIAL_FILE", credential)
            .env("NAVIGATOR_FAKE_DRIVER_CONTROL_SOCKET", &socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "fake did not create socket");
            std::thread::sleep(Duration::from_millis(10));
        }
        Self {
            _directory: directory,
            socket,
            child,
        }
    }

    fn client(&self) -> DriverClient {
        DriverClient::connect(
            &self.socket,
            DriverCredential::new(SECRET.to_vec()).unwrap(),
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

#[test]
fn authenticated_peer_is_served_while_original_channel_remains_open() {
    let mut harness = Harness::spawn();
    let mut original = harness.client();
    assert!(!original.describe().unwrap().implementation.is_empty());

    let started = Instant::now();
    let mut peer = original
        .connect_peer(&harness.socket, Duration::from_secs(2))
        .unwrap();
    assert!(!peer.describe().unwrap().implementation.is_empty());
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "peer was queued behind the still-open original channel"
    );
    std::thread::sleep(Duration::from_millis(2_200));
    assert!(!original.describe().unwrap().implementation.is_empty());

    drop(harness.child.stdin.take());
    let deadline = Instant::now() + Duration::from_secs(2);
    while harness.child.try_wait().unwrap().is_none() {
        assert!(
            Instant::now() < deadline,
            "ownership EOF did not stop all channels"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(original.describe().is_err());
    assert!(peer.describe().is_err());
}
