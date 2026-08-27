#![cfg(unix)]

use std::{
    fmt::Write as _,
    fs,
    io::Write,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

mod common;

use command_fds::{CommandFdExt, FdMapping};
use navigator_driver_client::{DriverClient, DriverCredential};
use navigator_driver_protocol::v1;
use tempfile::TempDir;

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

fn id(value: u8) -> Vec<u8> {
    vec![value; 16]
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn package() -> PathBuf {
    common::pi_package::built(&workspace_root())
}

fn provider(spawn: Option<(u8, u8, u8)>, label: &str) -> String {
    let module = workspace_root()
        .join("packages/navigator-driver-pi/node_modules/@earendil-works/pi-ai/dist/index.js");
    let mut responses = String::new();
    if let Some((request, template, grant)) = spawn {
        write!(responses, "fauxAssistantMessage(fauxToolCall('navigator_command',{{action:'spawn',request_id:'{request:02x}'.repeat(16),template_id:'{template:02x}'.repeat(16),task_input_base64:'e30=',grant_id:'{grant:02x}'.repeat(16)}}),{{stopReason:'toolUse'}}),").unwrap();
    }
    write!(responses, "fauxAssistantMessage(fauxToolCall('navigator_command',{{action:'report',kind:'succeeded',payload:'{label}'}}),{{stopReason:'toolUse'}}),fauxAssistantMessage('settled')").unwrap();
    format!(
        "import {{fauxAssistantMessage,fauxProvider,fauxToolCall}} from {:?}; export function register(runtime){{const faux=fauxProvider({{tokensPerSecond:1000}});faux.setResponses([{responses}]);runtime.registerNativeProvider(faux.provider);}}",
        format!("file://{}", module.display())
    )
}

struct Node {
    _dir: TempDir,
    socket: PathBuf,
    child: Child,
    ownership: UnixStream,
}

impl Node {
    fn spawn(source: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let credential = dir.path().join("credential");
        let socket = dir.path().join("control.sock");
        let provider = dir.path().join("provider.mjs");
        let bootstrap = dir.path().join("bootstrap.json");
        fs::write(&credential, SECRET).unwrap();
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&provider, source).unwrap();
        let runtime = serde_json::json!({"provider":"faux","model":"faux-1","authPath":dir.path().join("auth.json"),"providerModule":provider,"cwd":dir.path(),"tools":[]});
        fs::write(&bootstrap, runtime.to_string()).unwrap();
        fs::set_permissions(&bootstrap, fs::Permissions::from_mode(0o600)).unwrap();
        let (ownership, inherited) = UnixStream::pair().unwrap();
        let mut command = Command::new("node");
        command
            .args(["--preserve-symlinks", "dist/main.js"])
            .current_dir(package())
            .env("NAVIGATOR_CONTROL_SOCKET", &socket)
            .env("NAVIGATOR_CREDENTIAL_FILE", credential)
            .env("NAVIGATOR_DRIVER_ID", "01010101010101010101010101010101")
            .env("NAVIGATOR_DRIVER_BOOTSTRAP_FILE", bootstrap)
            .env("NAVIGATOR_DRIVER_PRIVATE_ROOT", dir.path())
            .env("NAVIGATOR_OWNERSHIP_FD", "3")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        command
            .fd_mappings(vec![FdMapping {
                parent_fd: inherited.into(),
                child_fd: 3,
            }])
            .unwrap();
        let child = command.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        while UnixStream::connect(&socket).is_err() {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        Self {
            _dir: dir,
            socket,
            child,
            ownership,
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

    fn revoke_and_wait(&mut self) {
        self.ownership.write_all(&[1]).unwrap();
        self.ownership.flush().unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while self.child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        assert!(!self.socket.exists());
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(node: &Node, base: u8) -> v1::InstanceIdentity {
    let trusted = common::valid_trusted_configuration("role fixture");
    node.client()
        .start(
            id(base),
            id(base + 1),
            id(base + 2),
            id(base + 3),
            id(base + 4),
            1,
            trusted,
        )
        .unwrap()
        .instance
        .unwrap()
}

fn drive_spawn(node: &Node, instance: v1::InstanceIdentity, base: u8, child: (u8, u8, u8)) {
    let delivery_instance = instance.clone();
    let socket = node.socket.clone();
    let delivery = thread::spawn(move || {
        DriverClient::connect(
            &socket,
            DriverCredential::new(SECRET.to_vec()).unwrap(),
            Duration::from_secs(3),
        )
        .unwrap()
        .deliver_attempt(
            id(base),
            delivery_instance,
            id(base + 1),
            id(base + 2),
            id(base + 3),
            b"work".to_vec(),
        )
        .unwrap()
    });
    assert!(matches!(
        node.client().observe(instance.clone(), 0).unwrap().event,
        Some(v1::driver_event::Event::Ready(_))
    ));
    let deadline = Instant::now() + Duration::from_secs(3);
    let event = loop {
        if let Ok(event) = node.client().observe(instance.clone(), 2) {
            break event;
        }
        assert!(
            Instant::now() < deadline,
            "hierarchy command was not emitted"
        );
        thread::sleep(Duration::from_millis(10));
    };
    let Some(v1::driver_event::Event::HierarchyCommand(command)) = &event.event else {
        panic!("missing hierarchy command")
    };
    assert_eq!(command.request_id, id(child.0));
    node.client()
        .hierarchy_result(
            id(base + 4),
            instance,
            command.request_id.clone(),
            v1::hierarchy_result_request::Result::Spawned(v1::SpawnChildResult {
                participant_id: id(child.0),
                operation_id: id(child.1),
                input_message_id: id(child.2),
            }),
        )
        .unwrap();
    assert_eq!(delivery.join().unwrap(), v1::Acceptance::Accepted);
}

#[test]
fn protocol_smoke_uses_three_isolated_pi_processes_and_stops_child_first() {
    let mut coordinator = Node::spawn(&provider(Some((40, 41, 42)), "coordinator-done"));
    let mut campaign = Node::spawn(&provider(Some((50, 51, 52)), "campaign-done"));
    let mut worker = Node::spawn(&provider(None, "worker-done"));
    let coordinator_identity = start(&coordinator, 10);
    let campaign_identity = start(&campaign, 20);
    let worker_identity = start(&worker, 30);
    drive_spawn(&coordinator, coordinator_identity.clone(), 60, (40, 41, 42));
    drive_spawn(&campaign, campaign_identity.clone(), 70, (50, 51, 52));

    let mut sibling_probe = worker.client();
    assert!(
        sibling_probe.inspect(campaign_identity).is_err(),
        "sibling identity crossed process boundary"
    );
    let mut worker_client = worker.client();
    assert_eq!(
        worker_client
            .deliver_attempt(
                id(80),
                worker_identity.clone(),
                id(81),
                id(82),
                id(83),
                b"work".to_vec()
            )
            .unwrap(),
        v1::Acceptance::Accepted
    );
    assert!(matches!(
        worker_client
            .observe(worker_identity.clone(), 1)
            .unwrap()
            .event,
        Some(v1::driver_event::Event::Acceptance(_))
    ));
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok(event) = worker.client().observe(worker_identity.clone(), 2) {
            assert!(matches!(
                event.event,
                Some(v1::driver_event::Event::Report(_))
            ));
            break;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }

    worker.revoke_and_wait();
    campaign.revoke_and_wait();
    coordinator.revoke_and_wait();
}
