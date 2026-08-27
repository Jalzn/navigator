#![cfg(unix)]

use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

mod common;

use command_fds::{CommandFdExt, FdMapping};
use navigator_driver_client::{DriverClient, DriverCredential, Observation};
use navigator_driver_protocol::v1;
use tempfile::TempDir;

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

fn id(value: u8) -> Vec<u8> {
    vec![value; 16]
}

fn observed(value: Observation) -> v1::DriverEvent {
    match value {
        Observation::Event(event) => *event,
        Observation::NoEvent => panic!("expected event"),
    }
}

fn package() -> PathBuf {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    common::pi_package::built(workspace)
}

struct TerminalDriver {
    _dir: TempDir,
    socket: PathBuf,
    child: Child,
    input: ChildStdin,
    ownership: UnixStream,
    output: mpsc::Receiver<String>,
}

impl TerminalDriver {
    fn spawn() -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = dir.path().join("control.sock");
        let credential = dir.path().join("credential");
        let provider = dir.path().join("provider.mjs");
        let bootstrap = dir.path().join("bootstrap.json");
        fs::write(&credential, SECRET).unwrap();
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).unwrap();
        let pi_ai = package().join("node_modules/@earendil-works/pi-ai/dist/index.js");
        fs::write(&provider, format!(
            "import{{fauxAssistantMessage,fauxProvider,fauxToolCall}}from {:?};export function register(runtime){{const p=fauxProvider({{tokensPerSecond:1000}});p.setResponses([fauxAssistantMessage('primed'),fauxAssistantMessage(fauxToolCall('navigator_command',{{action:'spawn',request_id:'28'.repeat(16),template_id:'29'.repeat(16),task_input_base64:'e30=',grant_id:'2a'.repeat(16)}}),{{stopReason:'toolUse'}}),fauxAssistantMessage(fauxToolCall('navigator_command',{{action:'report',kind:'succeeded',payload:'terminal'}}),{{stopReason:'toolUse'}}),fauxAssistantMessage('settled')]);runtime.registerNativeProvider(p.provider);}}",
            format!("file://{}", pi_ai.display())
        )).unwrap();
        let runtime = serde_json::json!({"provider":"faux","model":"faux-1","authPath":dir.path().join("auth.json"),"providerModule":provider,"terminalMode":"line","cwd":dir.path(),"tools":[]});
        fs::write(&bootstrap, runtime.to_string()).unwrap();
        fs::set_permissions(&bootstrap, fs::Permissions::from_mode(0o600)).unwrap();
        let (ownership, inherited) = UnixStream::pair().unwrap();
        let mut command = Command::new("script");
        command
            .args([
                "-q",
                "/dev/null",
                "node",
                "--preserve-symlinks",
                "dist/main.js",
            ])
            .current_dir(package())
            .env("NAVIGATOR_CONTROL_SOCKET", &socket)
            .env("NAVIGATOR_CREDENTIAL_FILE", credential)
            .env("NAVIGATOR_DRIVER_ID", "01010101010101010101010101010101")
            .env("NAVIGATOR_OWNERSHIP_FD", "3")
            .env("NAVIGATOR_DRIVER_BOOTSTRAP_FILE", bootstrap)
            .env("NAVIGATOR_DRIVER_PRIVATE_ROOT", dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        command
            .fd_mappings(vec![FdMapping {
                parent_fd: inherited.into(),
                child_fd: 3,
            }])
            .unwrap();
        let mut child = command.spawn().unwrap();
        let input = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, output) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let _ = sender.send(line);
            }
        });
        let deadline = Instant::now() + Duration::from_secs(8);
        while UnixStream::connect(&socket).is_err() {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        Self {
            _dir: dir,
            socket,
            child,
            input,
            ownership,
            output,
        }
    }

    fn client(&self) -> DriverClient {
        DriverClient::connect(
            &self.socket,
            DriverCredential::new(SECRET.to_vec()).unwrap(),
            Duration::from_secs(3),
        )
        .unwrap()
    }
}

impl Drop for TerminalDriver {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn production_line_terminal_uses_pty_while_fd3_retains_ownership() {
    let mut driver = TerminalDriver::spawn();
    let described = driver.client().describe().unwrap();
    let terminal = described
        .capabilities
        .iter()
        .find(|capability| capability.id == "interactive-terminal.v1")
        .unwrap();
    assert_eq!(terminal.parameters.len(), 1);
    assert_eq!(terminal.parameters[0].key, "mode");
    assert_eq!(terminal.parameters[0].value, "line");
    let trusted = common::valid_trusted_configuration("terminal fixture");
    let identity = driver
        .client()
        .start(id(3), id(4), id(5), id(6), id(7), 1, trusted)
        .unwrap()
        .instance
        .unwrap();
    assert!(matches!(
        observed(driver.client().observe(identity.clone(), 0).unwrap()).event,
        Some(v1::driver_event::Event::Ready(_))
    ));
    assert_eq!(
        driver
            .client()
            .deliver_attempt(
                id(8),
                identity.clone(),
                id(9),
                id(10),
                id(11),
                b"establish operation context".to_vec(),
            )
            .unwrap(),
        v1::Acceptance::Accepted
    );
    writeln!(driver.input, "run interactively").unwrap();
    driver.input.flush().unwrap();
    assert!(matches!(
        observed(driver.client().observe(identity.clone(), 1).unwrap()).event,
        Some(v1::driver_event::Event::Acceptance(_))
    ));
    let deadline = Instant::now() + Duration::from_secs(3);
    let hierarchy = loop {
        if let Ok(Observation::Event(event)) = driver.client().observe(identity.clone(), 2) {
            break event;
        }
        assert!(Instant::now() < deadline);
        thread::yield_now();
    };
    let Some(v1::driver_event::Event::HierarchyCommand(command)) = hierarchy.event else {
        panic!("interactive line did not emit a hierarchy command")
    };
    assert_eq!(command.request_id, id(40));
    driver
        .client()
        .hierarchy_result(
            id(12),
            identity.clone(),
            command.request_id,
            v1::hierarchy_result_request::Result::Spawned(v1::SpawnChildResult {
                participant_id: id(40),
                operation_id: id(41),
                input_message_id: id(42),
            }),
        )
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let line = driver
            .output
            .recv_timeout(remaining)
            .expect("terminal settlement was not printed");
        if line.contains("SETTLED") {
            break;
        }
    }
    assert!(matches!(
        driver.client().observe(identity, 3).unwrap(),
        Observation::NoEvent
    ));
    driver.ownership.write_all(&[1]).unwrap();
    driver.ownership.flush().unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while driver.child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline);
        thread::yield_now();
    }
    assert!(!driver.socket.exists());
}
