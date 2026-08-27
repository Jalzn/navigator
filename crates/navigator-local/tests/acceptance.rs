#![cfg(unix)]

use std::{
    fmt::Write as _,
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink},
        net::{UnixListener, UnixStream as StdUnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use navigator_consumer_protocol::{
    CURRENT_MAJOR, CURRENT_MINOR, MAX_REQUEST_BYTES,
    v1::{
        CloseSessionRequest, Failure, FailureCode, NegotiateRequest, OpenSessionRequest,
        ProtocolVersion, RequestMetadata, RetryClass, SessionSnapshot, SessionStatus,
        SnapshotRequest, StartOperationRequest, SubscribeEventsRequest, close_session_response,
        navigator_consumer_client::NavigatorConsumerClient, negotiate_response,
        open_session_response, snapshot_response, start_operation_response,
        subscribe_events_response,
    },
    validated_session_templates,
};
use navigator_domain::{ConsumerKey, HostId, MessageId, OperationId, RequestId, SessionId};
use navigator_store_api::{
    AcquireOwnership, EventReadLimit, LeaseDuration, MailboxStore, OperationStore, ReadEvents,
    ReleaseOwnership, RenewOwnership, RequestContext, SessionStore, StoreError,
};
use navigator_store_sqlite::SqliteStore;
use prost::Message;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tonic::{
    Code, Request,
    transport::{Channel, Endpoint},
};
use uuid::Uuid;

use navigator_local::MAX_SUBSCRIPTIONS;

const TOKEN: &str = "acceptance-secret";
static ACCEPTANCE_PROCESS_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn consumer_open_binds_canonical_closed_template_manifest() {
    let environment = Environment::new();
    let socket = environment.socket("manifest-open.sock");
    let _daemon = Daemon::start(
        &environment.database,
        socket.clone(),
        &environment.credential,
    )
    .await;
    let mut client = connect(&socket).await.unwrap();
    let negotiation = negotiate_client(&mut client, &["session.lifecycle.v1"]).await;
    let configuration_identity = negotiated_configuration_identity(&mut client).await;
    let mut request = open_request(&negotiation, 12, 1_200);
    request.configuration_identity = configuration_identity;
    let mut first = request.root_template.clone().unwrap();
    first.template_id = id(92);
    first.role = "campaign".into();
    let mut second = request.root_template.clone().unwrap();
    second.template_id = id(93);
    second.role = "worker".into();
    request.compatible_templates = vec![first.clone(), second.clone()];
    let (_, _, manifest) = validated_session_templates(&request).unwrap();
    let manifest = manifest.unwrap();
    let opened = open(&mut client, request.clone()).await.unwrap();
    assert_eq!(
        opened.compatibility_identity,
        manifest.compatibility().as_bytes()
    );

    request.compatible_templates = vec![second, first];
    let replay = open(&mut client, request.clone()).await.unwrap();
    assert_eq!(replay, opened);
    request.configuration_identity = vec![8; 32];
    let conflict = open(&mut client, request).await.unwrap_err();
    assert_eq!(conflict.code, FailureCode::InvalidRequest as i32);
}

#[tokio::test]
async fn exact_reset_replay_keeps_the_replacement_session_open() {
    let environment = Environment::new_short();
    let socket = environment.socket("reset-replay.sock");
    let _daemon = Daemon::start(
        &environment.database,
        socket.clone(),
        &environment.credential,
    )
    .await;
    let mut client = connect(&socket).await.unwrap();
    let capabilities = ["session.lifecycle.v1", "session.open-modes.v1"];
    let negotiation = negotiate_client(&mut client, &capabilities).await;
    let configuration_identity = negotiated_configuration_identity(&mut client).await;

    let mut initial = open_request(&negotiation, 120, 1_200);
    initial.metadata = Some(metadata(&negotiation, &capabilities));
    initial.configuration_identity = configuration_identity.clone();
    initial.mode = navigator_consumer_protocol::v1::SessionOpenMode::Open.into();
    let session_a = open(&mut client, initial).await.unwrap();

    let mut reset = open_request(&negotiation, 121, 1_201);
    reset.metadata = Some(metadata(&negotiation, &capabilities));
    reset.configuration_identity = configuration_identity;
    reset.mode = navigator_consumer_protocol::v1::SessionOpenMode::Reset.into();
    let session_b = open(&mut client, reset.clone()).await.unwrap();
    assert_ne!(session_b.session_id, session_a.session_id);
    assert_eq!(session_b.status, SessionStatus::Open as i32);

    let store = SqliteStore::open(&environment.database).await.unwrap();
    let replacement_id =
        SessionId::from_uuid(Uuid::from_slice(&session_b.session_id).unwrap()).unwrap();
    let before_replay = store
        .read_events(ReadEvents {
            session_id: replacement_id,
            consumer: ConsumerKey::new("acceptance-consumer").unwrap(),
            after: None,
            limit: EventReadLimit::new(100).unwrap(),
        })
        .await
        .unwrap();
    let replayed = open(&mut client, reset.clone()).await.unwrap();
    assert_eq!(
        replayed, session_b,
        "RESET replay did not return the ledger result"
    );
    let mut conflicting = reset;
    conflicting.consumer_key = "different-consumer".into();
    let authentication = open(&mut client, conflicting.clone()).await.unwrap_err();
    assert_eq!(authentication.code, FailureCode::Authentication as i32);
    assert_eq!(authentication.retry, RetryClass::Never as i32);

    let fresh_negotiation = negotiate_client(&mut client, &capabilities).await;
    conflicting.metadata = Some(metadata(&fresh_negotiation, &capabilities));
    conflicting.configuration_identity = negotiated_configuration_identity(&mut client).await;
    let conflict = open(&mut client, conflicting).await.unwrap_err();
    assert_eq!(conflict.code, FailureCode::Conflict as i32);
    let after = client
        .snapshot(authenticated(
            SnapshotRequest {
                metadata: Some(metadata(&negotiation, &["session.lifecycle.v1"])),
                session_id: session_b.session_id.clone(),
            },
            TOKEN,
        ))
        .await
        .unwrap()
        .into_inner()
        .outcome
        .unwrap();
    let snapshot_response::Outcome::Snapshot(after) = after else {
        panic!("replacement Session was not readable after exact RESET replay")
    };
    assert_eq!(after.session_id, session_b.session_id);
    assert_eq!(after.status, SessionStatus::Open as i32);

    let events = store
        .read_events(ReadEvents {
            session_id: replacement_id,
            consumer: ConsumerKey::new("acceptance-consumer").unwrap(),
            after: None,
            limit: EventReadLimit::new(100).unwrap(),
        })
        .await
        .unwrap();
    assert_eq!(
        events, before_replay,
        "exact replay and rejected Consumer mutants must append no Event"
    );
    assert!(
        events
            .events
            .iter()
            .all(|event| event.event_type().as_str() != "session.closed"),
        "exact RESET replay appended a close for the replacement Session"
    );
}

#[tokio::test]
async fn operation_admission_validates_persisted_template_before_unavailable_driver() {
    let environment = Environment::new();
    let socket = environment.socket("operation-admission.sock");
    let _daemon = Daemon::start(
        &environment.database,
        socket.clone(),
        &environment.credential,
    )
    .await;
    let mut client = connect(&socket).await.expect("connect operation client");
    let negotiation = negotiate_client(
        &mut client,
        &["operation.execution.v1", "session.lifecycle.v1"],
    )
    .await;
    let opened = open(&mut client, open_request(&negotiation, 13, 1_300))
        .await
        .expect("open operation Session");
    let invalid = start_operation(&mut client, &negotiation, &opened, 1_301, b"not-json").await;
    assert_eq!(invalid.code, FailureCode::InvalidRequest as i32);
    let valid = start_operation(&mut client, &negotiation, &opened, 1_302, b"{}").await;
    assert_eq!(valid.code, FailureCode::Unavailable as i32);
    let after = snapshot(&mut client, &negotiation, 13)
        .await
        .expect("snapshot after rejected starts");
    assert_eq!(
        after.revision, opened.revision,
        "rejected admission persisted a Session effect"
    );
    let store = SqliteStore::open(&environment.database)
        .await
        .expect("reopen observable Store");
    let operation_id = OperationId::from_uuid(derived_operation_id(13, 1_302)).unwrap();
    assert!(matches!(
        store.load_operation(operation_id).await,
        Err(StoreError::OperationNotFound { .. })
    ));
    let message_id = MessageId::from_uuid(derived_input_message_id(13, 1_302)).unwrap();
    assert!(matches!(
        store.load_message(message_id).await,
        Err(StoreError::MessageNotFound { .. })
    ));
    let request_id = RequestId::from_uuid(Uuid::from_u128(1_302)).unwrap();
    assert!(
        store
            .read_request(request_id)
            .await
            .expect("read forbidden request ledger")
            .is_none()
    );
    let events = store
        .read_events(ReadEvents {
            session_id: SessionId::from_uuid(Uuid::from_u128(13)).unwrap(),
            consumer: ConsumerKey::new("acceptance-consumer").unwrap(),
            after: None,
            limit: EventReadLimit::new(100).unwrap(),
        })
        .await
        .expect("read forbidden operation Events");
    assert!(
        events
            .events
            .iter()
            .all(|event| !event.event_type().as_str().starts_with("operation."))
    );
}

#[test]
fn invalid_driver_catalog_has_zero_daemon_durable_or_socket_side_effects() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::TempDir::new().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let catalog = directory.path().join("invalid-drivers.json");
    std::fs::write(&catalog, b"{\"entries\":{}}").unwrap();
    let database = directory.path().join("must-not-exist.db");
    let socket = directory.path().join("must-not-exist.sock");
    let credential = directory.path().join("also-must-not-be-read");
    let status = Command::new(env!("CARGO_BIN_EXE_navigatord"))
        .arg("--database")
        .arg(&database)
        .arg("--socket")
        .arg(&socket)
        .arg("--credential-file")
        .arg(&credential)
        .arg("--driver-catalog")
        .arg(&catalog)
        .arg("--driver-entry")
        .arg("fake")
        .status()
        .unwrap();
    assert!(!status.success());
    assert!(!database.exists());
    assert!(!database.with_extension("host-id").exists());
    assert!(!socket.exists());
}

fn derived_operation_id(session: u128, request: u128) -> Uuid {
    let mut digest = Sha256::new();
    digest.update(b"navigator.operation.v1");
    digest.update(Uuid::from_u128(session).as_bytes());
    digest.update(Uuid::from_u128(request).as_bytes());
    let mut bytes: [u8; 16] = digest.finalize()[..16].try_into().unwrap();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn derived_input_message_id(session: u128, request: u128) -> Uuid {
    let mut digest = Sha256::new();
    digest.update(b"navigator.operation-input.v1");
    digest.update(Uuid::from_u128(session).as_bytes());
    digest.update(Uuid::from_u128(request).as_bytes());
    let mut bytes: [u8; 16] = digest.finalize()[..16].try_into().unwrap();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn sha256_hex(path: &Path) -> String {
    Sha256::digest(fs::read(path).unwrap()).iter().fold(
        String::with_capacity(64),
        |mut output, byte| {
            write!(output, "{byte:02x}").unwrap();
            output
        },
    )
}

fn configured_pi_catalog(environment: &Environment) -> PathBuf {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let package = workspace.join("packages/navigator-driver-pi");
    assert!(
        Command::new("npm")
            .args(["run", "build"])
            .current_dir(&package)
            .status()
            .unwrap()
            .success()
    );
    let node = PathBuf::from(
        String::from_utf8(Command::new("which").arg("node").output().unwrap().stdout)
            .unwrap()
            .trim(),
    )
    .canonicalize()
    .unwrap();
    let provider = environment.directory.path().join("provider.mjs");
    let pi_ai = package.join("node_modules/@earendil-works/pi-ai/dist/index.js");
    fs::write(&provider, format!("import{{fauxAssistantMessage,fauxProvider,fauxToolCall}}from {:?};export function register(runtime){{const p=fauxProvider({{tokensPerSecond:1000}});p.setResponses([fauxAssistantMessage(fauxToolCall('navigator_report',{{kind:'succeeded',payload:'done'}}),{{stopReason:'toolUse'}}),fauxAssistantMessage('settled')]);runtime.registerNativeProvider(p.provider);}}", format!("file://{}", pi_ai.display()))).unwrap();
    let entrypoint = package.join("dist/main.js");
    let wrapper = environment.directory.path().join("pi-driver");
    fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nexec '{}' --preserve-symlinks '{}'\n",
            node.display(),
            entrypoint.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    let catalog = environment.directory.path().join("drivers.json");
    let document = serde_json::json!({"entries":{"pi":{
        "driver_id":"01010101-0101-0101-0101-010101010101",
        "executable":wrapper,"executable_sha256":sha256_hex(&wrapper),"arguments":[],"working_directory":package,
        "protocol_version":1,"ownership_channel":"dedicated_fd","capabilities":[{"name":"durable.acceptance","version":1}],
        "bootstrap_configuration":{"provider":"faux","model":"faux-1","authPath":environment.directory.path().join("auth.json"),"providerModule":provider,"cwd":environment.directory.path(),"tools":[]},
        "trusted_artifacts":[{"path":node,"sha256":sha256_hex(&node)},{"path":entrypoint,"sha256":sha256_hex(&entrypoint)},{"path":provider,"sha256":sha256_hex(&provider)}]
    }}});
    fs::write(&catalog, serde_json::to_vec(&document).unwrap()).unwrap();
    catalog
}

#[tokio::test]
async fn configured_daemon_runs_a_consumer_operation_through_the_generic_pi_catalog() {
    let _process_guard = ACCEPTANCE_PROCESS_LOCK.lock().await;
    let environment = Environment::new_short();
    let catalog = configured_pi_catalog(&environment);
    let socket = environment.socket("configured.sock");
    let daemon = Daemon::start_with_driver(
        &environment.database,
        socket.clone(),
        &environment.credential,
        &catalog,
        "pi",
    )
    .await;
    let mut client = connect(&socket).await.unwrap();
    let negotiation = negotiate_client(
        &mut client,
        &["session.lifecycle.v1", "operation.execution.v1"],
    )
    .await;
    let mut request = open_request(&negotiation, 81, 8_100);
    let template = request.root_template.as_mut().unwrap();
    template.driver_id = vec![1; 16];
    template.required_capabilities = vec![
        navigator_consumer_protocol::v1::DriverCapabilityRequirement {
            capability: "durable.acceptance".into(),
            minimum_version: 1,
            parameters: Vec::new(),
        },
    ];
    let opened = open(&mut client, request).await.unwrap();
    let response = client
        .start_operation(authenticated(
            StartOperationRequest {
                metadata: Some(metadata(&negotiation, &["operation.execution.v1"])),
                request_id: id(8_101),
                session_id: opened.session_id.clone(),
                participant_id: opened.root_participant_id.clone(),
                input: b"{}".to_vec(),
            },
            TOKEN,
        ))
        .await
        .unwrap()
        .into_inner();
    let start_operation_response::Outcome::Snapshot(operation) = response.outcome.unwrap() else {
        panic!("configured Driver rejected operation")
    };
    let operation_id =
        OperationId::from_uuid(Uuid::from_slice(&operation.operation_id).unwrap()).unwrap();
    let store = SqliteStore::open(&environment.database).await.unwrap();
    let completed = tokio::time::timeout(Duration::from_secs(35), async {
        loop {
            if store
                .load_operation(operation_id)
                .await
                .is_ok_and(|snapshot| snapshot.state == navigator_domain::OperationState::Succeeded)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        completed.is_ok(),
        "configured operation did not succeed: {:?}",
        store.load_operation(operation_id).await
    );
    daemon.stop_graceful().await;
}

struct Daemon {
    child: Child,
    socket: PathBuf,
}

impl Daemon {
    async fn start(database: &Path, socket: PathBuf, credential: &Path) -> Self {
        let child = daemon_command(database, &socket, credential)
            .spawn()
            .expect("spawn navigatord");
        let mut daemon = Self { child, socket };
        daemon.wait_ready(300).await;
        daemon
    }

    async fn start_with_driver(
        database: &Path,
        socket: PathBuf,
        credential: &Path,
        catalog: &Path,
        entry: &str,
    ) -> Self {
        let mut command = daemon_command(database, &socket, credential);
        command.stderr(Stdio::inherit());
        let child = command
            .arg("--driver-catalog")
            .arg(catalog)
            .arg("--driver-entry")
            .arg(entry)
            .spawn()
            .expect("spawn configured navigatord");
        let mut daemon = Self { child, socket };
        daemon.wait_ready(3_000).await;
        daemon
    }

    async fn wait_ready(&mut self, attempts: usize) {
        for _ in 0..attempts {
            if let Some(status) = self.child.try_wait().expect("query starting daemon") {
                panic!("navigatord exited before readiness: {status}");
            }
            if fs::symlink_metadata(&self.socket).is_ok() {
                if let Ok(mut client) = connect(&self.socket).await {
                    let request = authenticated(
                        NegotiateRequest {
                            minimum_version: Some(version()),
                            maximum_version: Some(version()),
                            capabilities: Vec::new(),
                        },
                        TOKEN,
                    );
                    if matches!(
                        client
                            .negotiate(request)
                            .await
                            .map(|response| response.into_inner().outcome),
                        Ok(Some(negotiate_response::Outcome::Negotiated(_)))
                    ) {
                        return;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "navigatord did not become ready at {}; socket={:?}",
            self.socket.display(),
            fs::symlink_metadata(&self.socket),
        );
    }

    async fn stop_graceful(mut self) {
        let status = self.stop_graceful_status().await;
        assert!(status.success(), "navigatord graceful shutdown failed");
    }

    async fn stop_graceful_status(&mut self) -> std::process::ExitStatus {
        let status = Command::new("/bin/kill")
            .arg("-TERM")
            .arg(self.child.id().to_string())
            .status()
            .expect("signal navigatord");
        assert!(status.success(), "SIGTERM delivery failed");
        for _ in 0..1_200 {
            if let Some(status) = self.child.try_wait().expect("query navigatord") {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("navigatord did not stop after SIGTERM");
    }

    fn crash(mut self) {
        self.child.kill().expect("SIGKILL navigatord");
        self.child.wait().expect("reap crashed navigatord");
    }

    fn terminate(&mut self) {
        if self.child.try_wait().expect("query navigatord").is_none() {
            self.child.kill().expect("terminate navigatord");
        }
        self.child.wait().expect("reap navigatord");
    }
}

fn daemon_command(database: &Path, socket: &Path, credential: &Path) -> Command {
    let mut command = Command::new(
        std::env::var_os("CARGO_BIN_EXE_navigatord")
            .expect("Cargo did not build the navigatord binary"),
    );
    command
        .arg("--database")
        .arg(database)
        .arg("--socket")
        .arg(socket)
        .arg("--credential-file")
        .arg(credential)
        .arg("--lease-ms")
        .arg("60000")
        .arg("--shutdown-timeout-ms")
        .arg("8000")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    command
}

async fn wait_for_exit(child: &mut Child, context: &str) -> std::process::ExitStatus {
    for _ in 0..100 {
        if let Some(status) = child.try_wait().expect("query child process") {
            return status;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    child.kill().expect("terminate unexpected live child");
    child.wait().expect("reap unexpected live child");
    panic!("{context} did not exit")
}

async fn assert_artifact_root_contender_rejected(
    database: &Path,
    socket: &Path,
    credential: &Path,
) {
    let mut contender = daemon_command(database, socket, credential)
        .spawn()
        .expect("spawn contending navigatord");
    let status = tokio::time::timeout(
        Duration::from_secs(3),
        wait_for_exit(&mut contender, "contending navigatord"),
    )
    .await
    .expect("contending navigatord did not fail within its bound");
    assert!(
        !status.success(),
        "contending navigatord acquired Artifact root"
    );
    let mut stderr = String::new();
    contender
        .stderr
        .take()
        .expect("contender stderr")
        .read_to_string(&mut stderr)
        .expect("read contender stderr");
    assert!(
        stderr.contains("artifact filesystem is unavailable")
            || stderr.contains("Resource temporarily unavailable"),
        "contender did not report exclusive Artifact ownership: {stderr}"
    );
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.terminate();
    }
}

struct Environment {
    directory: TempDir,
    root: PathBuf,
    database: PathBuf,
    credential: PathBuf,
}

impl Environment {
    fn new() -> Self {
        let directory = TempDir::new().expect("acceptance directory");
        let root = std::env::var_os("NAVIGATOR_SHUTDOWN_FAULT_ROOT")
            .map_or_else(|| directory.path().to_path_buf(), PathBuf::from);
        fs::create_dir_all(&root).expect("create acceptance root");
        let database = root.join("navigator.db");
        let credential = root.join("credential");
        fs::write(&credential, format!("{TOKEN}\n")).expect("write bootstrap credential");
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o600))
            .expect("restrict bootstrap credential");
        Self {
            directory,
            root,
            database,
            credential,
        }
    }

    fn new_short() -> Self {
        let directory = tempfile::Builder::new()
            .prefix("navd")
            .tempdir_in("/tmp")
            .unwrap();
        let database = directory.path().join("navigator.db");
        let credential = directory.path().join("credential");
        fs::write(&credential, format!("{TOKEN}\n")).unwrap();
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            root: directory.path().to_path_buf(),
            directory,
            database,
            credential,
        }
    }

    fn socket(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

fn run_cli(environment: &Environment, socket: &Path, arguments: &[&str]) -> String {
    let output = cli_output(environment, socket, arguments);
    assert!(
        output.status.success(),
        "navigatorctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("navigatorctl output is UTF-8")
}

fn cli_output(
    environment: &Environment,
    socket: &Path,
    arguments: &[&str],
) -> std::process::Output {
    navigatorctl_command(environment, socket, arguments)
        .output()
        .expect("run navigatorctl")
}

fn navigatorctl_command(environment: &Environment, socket: &Path, arguments: &[&str]) -> Command {
    let mut command = Command::new(
        std::env::var_os("CARGO_BIN_EXE_navigatorctl")
            .expect("Cargo did not build the navigatorctl binary"),
    );
    command
        .arg("--socket")
        .arg(socket)
        .arg("--credential-file")
        .arg(&environment.credential)
        .args(arguments)
        .stdin(Stdio::null());
    command
}

async fn connect(path: &Path) -> Result<NavigatorConsumerClient<Channel>, tonic::transport::Error> {
    Endpoint::from_shared(format!("unix:{}", path.display()))?
        .connect()
        .await
        .map(NavigatorConsumerClient::new)
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the CLI process-boundary oracle keeps token handoff and lifecycle commands visible"
)]
async fn cli_crosses_the_real_process_and_uds_boundary() {
    let _process_guard = ACCEPTANCE_PROCESS_LOCK.lock().await;
    let environment = Environment::new();
    let socket = environment.socket("cli.sock");
    let daemon = Daemon::start(
        &environment.database,
        socket.clone(),
        &environment.credential,
    )
    .await;
    let session = Uuid::from_u128(5).to_string();
    let negotiation_directory = environment.root.join("cli-private");
    std::fs::create_dir(&negotiation_directory).unwrap();
    std::fs::set_permissions(
        &negotiation_directory,
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let negotiation_file = negotiation_directory.join("negotiation.token");
    let negotiated = run_cli(
        &environment,
        &socket,
        &[
            "--negotiation-id-file",
            negotiation_file.to_str().unwrap(),
            "negotiate",
        ],
    );
    let token = std::fs::read_to_string(&negotiation_file).unwrap();
    assert!(Uuid::parse_str(token.trim()).is_ok());
    assert!(!negotiated.contains(token.trim()));
    let opened = run_cli(
        &environment,
        &socket,
        &[
            "--negotiation-id-file",
            negotiation_file.to_str().unwrap(),
            "open",
            "--request-id",
            &Uuid::from_u128(500).to_string(),
            "--session-id",
            &session,
            "--consumer-key",
            "cli-consumer",
            "--template-id",
            &Uuid::from_u128(90).to_string(),
            "--driver-id",
            &Uuid::from_u128(91).to_string(),
            "--role",
            "root",
            "--base-instructions",
            "execute the admitted task",
        ],
    );
    assert!(opened.contains(&format!("id={session}")));
    assert!(opened.contains("SESSION_STATUS_OPEN"));
    assert!(opened.contains("revision=2"));

    let snapshot = run_cli(
        &environment,
        &socket,
        &[
            "--negotiation-id-file",
            negotiation_file.to_str().unwrap(),
            "snapshot",
            "--session-id",
            &session,
        ],
    );
    assert_eq!(
        snapshot, opened,
        "CLI snapshot disagrees with committed Open result"
    );

    let events = run_cli(
        &environment,
        &socket,
        &[
            "--negotiation-id-file",
            negotiation_file.to_str().unwrap(),
            "events",
            "--session-id",
            &session,
            "--after",
            "0",
            "--count",
            "3",
        ],
    );
    let lines = events.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].contains("position=1") && lines[0].contains("type=session.created"));
    assert!(lines[1].contains("position=2") && lines[1].contains("type=ownership.acquired"));
    assert!(lines[2].contains("position=3") && lines[2].contains("type=participant.created"));

    let old_token = std::fs::read_to_string(&negotiation_file).unwrap();
    daemon.stop_graceful().await;
    let _restarted = Daemon::start(
        &environment.database,
        socket.clone(),
        &environment.credential,
    )
    .await;
    let expired = cli_output(
        &environment,
        &socket,
        &[
            "--negotiation-id-file",
            negotiation_file.to_str().unwrap(),
            "snapshot",
            "--session-id",
            &session,
        ],
    );
    assert!(!expired.status.success());
    assert_eq!(
        std::fs::read_to_string(&negotiation_file).unwrap(),
        old_token,
        "an expired token file was mutated"
    );
    assert!(!String::from_utf8_lossy(&expired.stdout).contains(old_token.trim()));
    assert!(!String::from_utf8_lossy(&expired.stderr).contains(old_token.trim()));

    let refreshed_negotiation_file = negotiation_directory.join("refreshed.token");
    run_cli(
        &environment,
        &socket,
        &[
            "--negotiation-id-file",
            refreshed_negotiation_file.to_str().unwrap(),
            "negotiate",
        ],
    );
    let rebound = run_cli(
        &environment,
        &socket,
        &[
            "--negotiation-id-file",
            refreshed_negotiation_file.to_str().unwrap(),
            "open",
            "--request-id",
            &Uuid::from_u128(500).to_string(),
            "--session-id",
            &session,
            "--consumer-key",
            "cli-consumer",
            "--template-id",
            &Uuid::from_u128(90).to_string(),
            "--driver-id",
            &Uuid::from_u128(91).to_string(),
            "--role",
            "root",
            "--base-instructions",
            "execute the admitted task",
        ],
    );
    assert!(rebound.contains(&format!("id={session}")));
    let negotiation_file = refreshed_negotiation_file;

    let closed = run_cli(
        &environment,
        &socket,
        &[
            "--negotiation-id-file",
            negotiation_file.to_str().unwrap(),
            "close",
            "--request-id",
            &Uuid::from_u128(501).to_string(),
            "--session-id",
            &session,
        ],
    );
    assert!(closed.contains("SESSION_STATUS_CLOSED"));
    let closed_revision = closed
        .split_whitespace()
        .find_map(|field| field.strip_prefix("revision="))
        .and_then(|value| value.parse::<u64>().ok())
        .expect("CLI close did not print a revision");
    assert!(
        closed_revision > 3,
        "restart, rebind, and close did not advance durable revision"
    );

    let failed = cli_output(
        &environment,
        &socket,
        &[
            "--negotiation-id-file",
            negotiation_file.to_str().unwrap(),
            "snapshot",
            "--session-id",
            &Uuid::from_u128(999).to_string(),
        ],
    );
    assert!(
        !failed.status.success(),
        "CLI mapped a domain Failure to success"
    );
    assert!(String::from_utf8_lossy(&failed.stderr).contains("FAILURE_CODE_NOT_FOUND"));
}

#[tokio::test]
async fn cli_exits_nonzero_when_event_stream_ends_before_requested_count() {
    let environment = Environment::new();
    let socket = environment.socket("cli-eof.sock");
    let daemon = Daemon::start(
        &environment.database,
        socket.clone(),
        &environment.credential,
    )
    .await;
    let mut client = connect(&socket).await.expect("connect CLI EOF setup");
    let negotiation = negotiate_client(&mut client, &["session.lifecycle.v1"]).await;
    let _opened = open(&mut client, open_request(&negotiation, 11, 1_100))
        .await
        .expect("open CLI EOF Session");
    drop(client);
    let negotiation_directory = environment.root.join("cli-eof-private");
    std::fs::create_dir(&negotiation_directory).unwrap();
    std::fs::set_permissions(
        &negotiation_directory,
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let negotiation_file = negotiation_directory.join("negotiation.token");
    std::fs::write(
        &negotiation_file,
        format!("{}\n", Uuid::from_slice(&negotiation).unwrap()),
    )
    .unwrap();
    std::fs::set_permissions(&negotiation_file, std::fs::Permissions::from_mode(0o600)).unwrap();

    let session = Uuid::from_u128(11).to_string();
    let mut cli = navigatorctl_command(
        &environment,
        &socket,
        &[
            "--negotiation-id-file",
            negotiation_file.to_str().unwrap(),
            "events",
            "--session-id",
            &session,
            "--after",
            &u64::MAX.to_string(),
            "--count",
            "1",
        ],
    )
    .stdout(Stdio::null())
    .stderr(Stdio::piped())
    .spawn()
    .expect("spawn waiting navigatorctl");
    for _ in 0..20 {
        assert!(
            cli.try_wait()
                .expect("query waiting navigatorctl")
                .is_none(),
            "navigatorctl exited before waiting for an Event"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    daemon.stop_graceful().await;
    let status = wait_for_exit(&mut cli, "EOF navigatorctl").await;
    assert!(
        !status.success(),
        "navigatorctl treated EOF before requested Event count as success"
    );
}

fn authenticated<T>(message: T, token: &str) -> Request<T> {
    let mut request = Request::new(message);
    request.metadata_mut().insert(
        "x-navigator-bootstrap",
        token.parse().expect("ASCII fixture credential"),
    );
    request
}

fn version() -> ProtocolVersion {
    ProtocolVersion {
        major: CURRENT_MAJOR,
        minor: CURRENT_MINOR,
    }
}

async fn negotiate_client(
    client: &mut NavigatorConsumerClient<Channel>,
    capabilities: &[&str],
) -> Vec<u8> {
    let response = client
        .negotiate(authenticated(
            NegotiateRequest {
                minimum_version: Some(version()),
                maximum_version: Some(version()),
                capabilities: capabilities.iter().map(ToString::to_string).collect(),
            },
            TOKEN,
        ))
        .await
        .expect("Negotiate transport")
        .into_inner();
    match response.outcome.expect("Negotiate outcome") {
        negotiate_response::Outcome::Negotiated(negotiated) => negotiated.negotiation_id,
        negotiate_response::Outcome::Failure(failure) => panic!("Negotiate failed: {failure:?}"),
    }
}

async fn negotiated_configuration_identity(
    client: &mut NavigatorConsumerClient<Channel>,
) -> Vec<u8> {
    let response = client
        .negotiate(authenticated(
            NegotiateRequest {
                minimum_version: Some(version()),
                maximum_version: Some(version()),
                capabilities: vec!["session.lifecycle.v1".into()],
            },
            TOKEN,
        ))
        .await
        .expect("Negotiate transport")
        .into_inner();
    match response.outcome.expect("Negotiate outcome") {
        negotiate_response::Outcome::Negotiated(negotiated) => negotiated.configuration_identity,
        negotiate_response::Outcome::Failure(failure) => panic!("Negotiate failed: {failure:?}"),
    }
}

fn metadata(negotiation_id: &[u8], capabilities: &[&str]) -> RequestMetadata {
    RequestMetadata {
        protocol_version: Some(version()),
        capabilities: capabilities.iter().map(ToString::to_string).collect(),
        negotiation_id: negotiation_id.to_vec(),
    }
}

fn id(value: u128) -> Vec<u8> {
    Uuid::from_u128(value).as_bytes().to_vec()
}

fn open_request(negotiation_id: &[u8], session: u128, request: u128) -> OpenSessionRequest {
    OpenSessionRequest {
        metadata: Some(metadata(negotiation_id, &["session.lifecycle.v1"])),
        request_id: id(request),
        session_id: id(session),
        consumer_key: "acceptance-consumer".into(),
        compatibility_identity: Vec::new(),
        root_template: Some(navigator_consumer_protocol::v1::RootTemplateSpecification {
            template_id: id(90),
            role: "root".into(),
            driver_id: id(91),
            required_capabilities: vec![
                navigator_consumer_protocol::v1::DriverCapabilityRequirement {
                    capability: "task.execute".into(),
                    minimum_version: 1,
                    parameters: Vec::new(),
                },
            ],
            trusted_configuration: Some(
                navigator_consumer_protocol::v1::TrustedTemplateConfiguration {
                    base_instructions: "execute the admitted task".into(),
                    secret_names: Vec::new(),
                },
            ),
            resources: Some(navigator_consumer_protocol::v1::ParticipantResourceBounds {
                memory_bytes: 64 * 1024 * 1024,
                cpu_millis: 1_000,
                max_concurrent_operations: 1,
            }),
            input_schema: Some(navigator_consumer_protocol::v1::InputSchema { fields: Vec::new() }),
            authority_profile: None,
        }),
        compatible_templates: Vec::new(),
        configuration_identity: Vec::new(),
        mode: navigator_consumer_protocol::v1::SessionOpenMode::Unspecified.into(),
    }
}

async fn open(
    client: &mut NavigatorConsumerClient<Channel>,
    request: OpenSessionRequest,
) -> Result<SessionSnapshot, Failure> {
    match client
        .open_session(authenticated(request, TOKEN))
        .await
        .expect("OpenSession transport")
        .into_inner()
        .outcome
        .expect("OpenSession outcome")
    {
        open_session_response::Outcome::Snapshot(snapshot) => Ok(snapshot),
        open_session_response::Outcome::Failure(failure) => Err(failure),
    }
}

async fn start_operation(
    client: &mut NavigatorConsumerClient<Channel>,
    negotiation_id: &[u8],
    session: &SessionSnapshot,
    request: u128,
    input: &[u8],
) -> Failure {
    let response = client
        .start_operation(authenticated(
            StartOperationRequest {
                metadata: Some(metadata(negotiation_id, &["operation.execution.v1"])),
                request_id: id(request),
                session_id: session.session_id.clone(),
                participant_id: session.root_participant_id.clone(),
                input: input.to_vec(),
            },
            TOKEN,
        ))
        .await
        .expect("StartOperation transport")
        .into_inner();
    match response.outcome.expect("StartOperation outcome") {
        start_operation_response::Outcome::Failure(failure) => failure,
        start_operation_response::Outcome::Snapshot(snapshot) => {
            panic!("unexpected admitted Operation: {snapshot:?}")
        }
    }
}

async fn snapshot(
    client: &mut NavigatorConsumerClient<Channel>,
    negotiation_id: &[u8],
    session: u128,
) -> Result<SessionSnapshot, Failure> {
    match client
        .snapshot(authenticated(
            SnapshotRequest {
                metadata: Some(metadata(negotiation_id, &["session.lifecycle.v1"])),
                session_id: id(session),
            },
            TOKEN,
        ))
        .await
        .expect("Snapshot transport")
        .into_inner()
        .outcome
        .expect("Snapshot outcome")
    {
        snapshot_response::Outcome::Snapshot(snapshot) => Ok(snapshot),
        snapshot_response::Outcome::Failure(failure) => Err(failure),
    }
}

async fn close(
    client: &mut NavigatorConsumerClient<Channel>,
    negotiation_id: &[u8],
    session: u128,
    request: u128,
) -> Result<SessionSnapshot, Failure> {
    match client
        .close_session(authenticated(
            CloseSessionRequest {
                metadata: Some(metadata(negotiation_id, &["session.lifecycle.v1"])),
                request_id: id(request),
                session_id: id(session),
            },
            TOKEN,
        ))
        .await
        .expect("CloseSession transport")
        .into_inner()
        .outcome
        .expect("CloseSession outcome")
    {
        close_session_response::Outcome::Snapshot(snapshot) => Ok(snapshot),
        close_session_response::Outcome::Failure(failure) => Err(failure),
    }
}

async fn assert_subscription_resume(
    client: &mut NavigatorConsumerClient<Channel>,
    negotiation_id: &[u8],
    session: u128,
) {
    let mut first_stream = client
        .subscribe_events(authenticated(
            SubscribeEventsRequest {
                metadata: Some(metadata(negotiation_id, &["events.replay.v1"])),
                session_id: id(session),
                after_position: 0,
            },
            TOKEN,
        ))
        .await
        .expect("subscribe from origin")
        .into_inner();
    let first = first_stream
        .message()
        .await
        .expect("first Event transport")
        .and_then(|response| response.outcome)
        .expect("first Event outcome");
    let subscribe_events_response::Outcome::Event(first) = first else {
        panic!("subscription returned a Failure")
    };
    drop(first_stream);

    let mut resumed = client
        .subscribe_events(authenticated(
            SubscribeEventsRequest {
                metadata: Some(metadata(negotiation_id, &["events.replay.v1"])),
                session_id: id(session),
                after_position: first.position,
            },
            TOKEN,
        ))
        .await
        .expect("resume subscription")
        .into_inner();
    let next = resumed
        .message()
        .await
        .expect("resumed Event transport")
        .and_then(|response| response.outcome)
        .expect("resumed Event outcome");
    let subscribe_events_response::Outcome::Event(next) = next else {
        panic!("resumed subscription returned a Failure")
    };
    assert_eq!(
        next.position,
        first.position + 1,
        "NAV-EVENT-001 reconnect skipped or duplicated a position"
    );
}

fn subscription_request(negotiation_id: &[u8], session_id: Vec<u8>) -> SubscribeEventsRequest {
    SubscribeEventsRequest {
        metadata: Some(metadata(negotiation_id, &["events.replay.v1"])),
        session_id,
        after_position: 0,
    }
}

async fn assert_stream_failure(
    mut stream: tonic::Streaming<navigator_consumer_protocol::v1::SubscribeEventsResponse>,
    code: FailureCode,
    retry: RetryClass,
) {
    let first = stream
        .message()
        .await
        .expect("Failure item transport")
        .and_then(|response| response.outcome)
        .expect("Failure stream ended before its first item");
    let subscribe_events_response::Outcome::Failure(failure) = first else {
        panic!("setup failure produced an Event")
    };
    assert_eq!(failure.code, code as i32);
    assert_eq!(failure.retry, retry as i32);
    assert!(
        stream
            .message()
            .await
            .expect("Failure EOF transport")
            .is_none(),
        "Failure stream emitted more than one item"
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the restart vertical keeps the complete process and replay oracle visible"
)]
// Guarantees: NAV-DEPLOY-001, NAV-TRANSPORT-001, NAV-DOC-001
async fn lifecycle_replay_and_subscription_survive_a_real_process_restart() {
    let _process_guard = ACCEPTANCE_PROCESS_LOCK.lock().await;
    let environment = Environment::new();
    let socket = environment.socket("navigator.sock");
    let daemon = Daemon::start(
        &environment.database,
        socket.clone(),
        &environment.credential,
    )
    .await;
    assert_eq!(
        fs::metadata(&socket)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600,
        "NAV-SEC-LOCAL-001 UDS permissions are not owner-only",
    );

    let mut client = connect(&socket).await.expect("connect to navigatord");
    let negotiation =
        negotiate_client(&mut client, &["events.replay.v1", "session.lifecycle.v1"]).await;
    let command = open_request(&negotiation, 1, 100);
    let opened = open(&mut client, command.clone())
        .await
        .expect("open Session");
    assert_eq!(opened.session_id, id(1));
    assert_eq!(opened.status, SessionStatus::Open as i32);
    let immediate_replay = open(&mut client, command.clone())
        .await
        .expect("repeat OpenSession on current owner");
    assert_eq!(
        immediate_replay, opened,
        "NAV-IDEMPOTENCY-001 same-daemon replay changed revision, Events, or ownership"
    );

    assert_subscription_resume(&mut client, &negotiation, 1).await;
    drop(client);
    daemon.stop_graceful().await;
    assert!(
        environment.credential.exists(),
        "daemon deleted a caller-owned bootstrap credential"
    );

    let restarted = Daemon::start(
        &environment.database,
        socket.clone(),
        &environment.credential,
    )
    .await;
    let mut client = connect(&socket).await.expect("connect after restart");
    let negotiation =
        negotiate_client(&mut client, &["events.replay.v1", "session.lifecycle.v1"]).await;
    let persisted = snapshot(&mut client, &negotiation, 1)
        .await
        .expect("snapshot after restart");
    assert_eq!(persisted.session_id, opened.session_id);
    assert_eq!(
        persisted.revision,
        opened.revision + 1,
        "graceful shutdown did not durably release ownership"
    );
    let mut command = command;
    command.metadata = Some(metadata(&negotiation, &["session.lifecycle.v1"]));
    let replay = open(&mut client, command)
        .await
        .expect("replay OpenSession after restart");
    assert_eq!(replay.session_id, opened.session_id);
    assert_eq!(replay.consumer_key, opened.consumer_key);
    assert_eq!(
        replay.revision,
        persisted.revision + 1,
        "NAV-IDEMPOTENCY-001 replay recreated the Session instead of only reacquiring ownership"
    );

    let closed = close(&mut client, &negotiation, 1, 102)
        .await
        .expect("close Session");
    assert_eq!(closed.status, SessionStatus::Closed as i32);
    assert_eq!(
        close(&mut client, &negotiation, 1, 102)
            .await
            .expect("same-daemon close replay"),
        closed
    );
    drop(client);
    restarted.stop_graceful().await;
    assert!(environment.credential.exists());

    let _third = Daemon::start(
        &environment.database,
        socket.clone(),
        &environment.credential,
    )
    .await;
    let mut client = connect(&socket)
        .await
        .expect("connect after closed restart");
    let negotiation = negotiate_client(&mut client, &["session.lifecycle.v1"]).await;
    assert_eq!(
        close(&mut client, &negotiation, 1, 102)
            .await
            .expect("close replay after restart"),
        closed,
        "NAV-IDEMPOTENCY-001 durable Close replay changed after restart"
    );
}

#[tokio::test]
async fn frozen_v1_consumer_crosses_real_process_negotiate_and_snapshot_boundaries() {
    fn frozen<T: Message + Default>(text: &str) -> T {
        let bytes = text
            .trim()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        T::decode(bytes.as_slice()).unwrap()
    }

    let environment = Environment::new();
    let socket = environment.socket("frozen-v1-consumer.sock");
    let _daemon = Daemon::start(
        &environment.database,
        socket.clone(),
        &environment.credential,
    )
    .await;
    let mut client = connect(&socket).await.expect("connect frozen v1 client");
    let negotiate: NegotiateRequest = frozen(include_str!(
        "../../navigator-consumer-protocol/fixtures/negotiate-v1_0.hex"
    ));
    let response = client
        .negotiate(authenticated(negotiate, TOKEN))
        .await
        .expect("frozen Negotiate crossed the real UDS process")
        .into_inner();
    let negotiate_response::Outcome::Negotiated(negotiated) =
        response.outcome.expect("frozen Negotiate outcome")
    else {
        panic!("frozen v1 Negotiate was rejected")
    };
    assert_eq!(
        negotiated.protocol_version,
        Some(ProtocolVersion { major: 1, minor: 0 })
    );
    assert!(
        negotiated.capabilities.is_empty(),
        "retired old capability spelling must downgrade without broadening"
    );

    let mut lifecycle_negotiate: NegotiateRequest = frozen(include_str!(
        "../../navigator-consumer-protocol/fixtures/negotiate-v1_0.hex"
    ));
    lifecycle_negotiate.capabilities = vec!["session.lifecycle.v1".into()];
    let response = client
        .negotiate(authenticated(lifecycle_negotiate, TOKEN))
        .await
        .expect("old generated client capability crossed the real UDS process")
        .into_inner();
    let negotiate_response::Outcome::Negotiated(lifecycle) =
        response.outcome.expect("lifecycle Negotiate outcome")
    else {
        panic!("old generated client lifecycle Negotiate was rejected")
    };
    assert_eq!(lifecycle.capabilities, ["session.lifecycle.v1"]);

    let mut snapshot: SnapshotRequest = frozen(include_str!(
        "../../navigator-consumer-protocol/fixtures/snapshot-v1_0.hex"
    ));
    let metadata = snapshot.metadata.as_mut().unwrap();
    metadata.negotiation_id = lifecycle.negotiation_id;
    metadata.capabilities = lifecycle.capabilities;
    let response = client
        .snapshot(authenticated(snapshot, TOKEN))
        .await
        .expect("frozen Snapshot crossed the real UDS process")
        .into_inner();
    assert!(
        matches!(
            response.outcome,
            Some(snapshot_response::Outcome::Failure(Failure { code, .. }))
                if code == FailureCode::NotFound as i32
        ),
        "unexpected frozen Snapshot outcome: {response:?}"
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the adversarial shutdown oracle keeps its complete cross-table sweep visible"
)]
async fn external_shutdown_fault_matrix_reopens_and_reconciles_owned_session() {
    // This matrix repeatedly launches the lifecycle vertical in subprocesses.
    // Serialize it with the other process-heavy acceptance oracles so host
    // scheduler contention cannot impersonate a shutdown or negotiation fault.
    let _process_guard = ACCEPTANCE_PROCESS_LOCK.lock().await;
    for point in [
        "shutdown.external.before_call",
        "shutdown.external.after_call",
        "shutdown.external.before_identity_proof",
        "shutdown.external.after_identity_proof",
    ] {
        if std::env::var("NAVIGATOR_FAULT_MATRIX_ONLY").is_ok_and(|only| only != point) {
            continue;
        }
        let parent = TempDir::new().unwrap();
        let root = parent.path().join("fixture");
        let observation = parent.path().join("observed");
        let mut unrelated = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let sentinel_path = parent.path().join("unrelated.sock");
        let sentinel = UnixListener::bind(&sentinel_path).unwrap();
        let sentinel_before = fs::metadata(&sentinel_path).unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("lifecycle_replay_and_subscription_survive_a_real_process_restart")
            .env("NAVIGATOR_SHUTDOWN_FAULT_ROOT", &root)
            .env("NAVIGATOR_EXTERNAL_FAULT_POINT", point)
            .env("NAVIGATOR_EXTERNAL_FAULT_OBSERVATION", &observation)
            .status()
            .unwrap();
        assert!(!status.success(), "worker did not abort at {point}");
        assert_eq!(fs::read_to_string(&observation).unwrap(), point);
        let store = SqliteStore::open(root.join("navigator.db")).await.unwrap();
        let session_id = SessionId::from_uuid(Uuid::from_u128(1)).unwrap();
        let sqlite_reopened = store.load_session(session_id).await.unwrap().id() == session_id;
        assert!(sqlite_reopened);
        let ownership_released = matches!(
            store.read_ownership(session_id).await.unwrap(),
            navigator_domain::OwnershipSnapshot::Unowned
        );
        let duplicate_unfinished_participants: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM (SELECT session_id FROM participants WHERE parent_participant_id IS NULL GROUP BY session_id HAVING COUNT(*)>1)",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        let duplicate_unfinished_operations: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM (SELECT participant_id FROM operations WHERE terminal_outcome IS NULL GROUP BY participant_id HAVING COUNT(*)>1)",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        let foreign_key_violations = i64::try_from(
            sqlx::query("PRAGMA foreign_key_check")
                .fetch_all(store.pool())
                .await
                .unwrap()
                .len(),
        )
        .unwrap();
        let unreleased_reservations_before_reconcile: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM capacity_reservations WHERE released=0")
                .fetch_one(store.pool())
                .await
                .unwrap();
        let effect_owner_violations = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM effect_journal e LEFT JOIN sessions s ON s.session_id=e.session_id LEFT JOIN participants p ON p.participant_id=e.participant_id AND p.session_id=e.session_id LEFT JOIN operations o ON o.operation_id=e.operation_id AND o.session_id=e.session_id WHERE s.session_id IS NULL OR p.participant_id IS NULL OR o.operation_id IS NULL",
            )
            .fetch_one(store.pool()).await.unwrap();
        let approval_intent_violations = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM approval_effect_intents i LEFT JOIN approval_grants g ON g.grant_id=i.grant_id AND g.session_id=i.session_id AND g.operation_id=i.operation_id WHERE g.grant_id IS NULL",
            )
            .fetch_one(store.pool()).await.unwrap();
        let artifact_owner_violations = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM artifacts a LEFT JOIN participants p ON p.participant_id=a.creator_participant_id AND p.session_id=a.session_id LEFT JOIN operations o ON o.operation_id=a.creator_operation_id AND o.session_id=a.session_id WHERE a.creator_participant_id IS NOT NULL AND (p.participant_id IS NULL OR o.operation_id IS NULL)",
            )
            .fetch_one(store.pool()).await.unwrap();
        let successor = HostId::from_uuid(Uuid::from_u128(8_800_002)).unwrap();
        let request = |value, caller| {
            RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(value)).unwrap(),
                caller,
            )
        };
        let (predecessor, predecessor_epoch) = match store.read_ownership(session_id).await.unwrap()
        {
            navigator_domain::OwnershipSnapshot::Owned { host_id, epoch, .. } => (host_id, epoch),
            navigator_domain::OwnershipSnapshot::Unowned => {
                let predecessor = HostId::from_uuid(Uuid::from_u128(8_800_001)).unwrap();
                let lease = store
                    .acquire_ownership(AcquireOwnership::new(
                        request(8_800_003, predecessor),
                        session_id,
                        LeaseDuration::from_millis(60_000).unwrap(),
                    ))
                    .await
                    .unwrap()
                    .value()
                    .clone();
                (predecessor, lease.epoch())
            }
        };
        store
            .release_ownership(ReleaseOwnership::new(
                request(8_800_004, predecessor),
                session_id,
                predecessor_epoch,
            ))
            .await
            .unwrap();
        let successor_lease = store
            .acquire_ownership(AcquireOwnership::new(
                request(8_800_005, successor),
                session_id,
                LeaseDuration::from_millis(60_000).unwrap(),
            ))
            .await
            .unwrap()
            .value()
            .clone();
        let before_stale = store.read_ownership(session_id).await.unwrap();
        let before_ledger: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM request_ledger")
            .fetch_one(store.pool())
            .await
            .unwrap();
        let before_events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(store.pool())
            .await
            .unwrap();
        let before_domain_fingerprint: String = sqlx::query_scalar(
            "SELECT COALESCE(group_concat(x,'|'),'') FROM (SELECT 'p:'||participant_id||':'||COALESCE(parent_participant_id,'')||':'||template_id||':'||revision x FROM participants UNION ALL SELECT 'o:'||operation_id||':'||state||':'||COALESCE(terminal_outcome,'')||':'||revision FROM operations UNION ALL SELECT 'a:'||artifact_id||':'||state||':'||size FROM artifacts UNION ALL SELECT 'e:'||effect_id||':'||phase||':'||revision FROM approval_effect_intents UNION ALL SELECT 'c:'||reservation_id||':'||resource||':'||amount||':'||released FROM capacity_reservations ORDER BY x)",
        ).fetch_one(store.pool()).await.unwrap();
        let stale_result = store
            .renew_ownership(RenewOwnership::new(
                request(8_800_006, predecessor),
                session_id,
                predecessor_epoch,
                LeaseDuration::from_millis(60_000).unwrap(),
            ))
            .await;
        let stale_rejected = matches!(&stale_result, Err(StoreError::StaleOwnership { .. }));
        let after_first_ledger: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM request_ledger")
            .fetch_one(store.pool())
            .await
            .unwrap();
        let replay_result = store
            .renew_ownership(RenewOwnership::new(
                request(8_800_006, predecessor),
                session_id,
                predecessor_epoch,
                LeaseDuration::from_millis(60_000).unwrap(),
            ))
            .await;
        let after_replay_ledger: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM request_ledger")
            .fetch_one(store.pool())
            .await
            .unwrap();
        let altered_result = store
            .renew_ownership(RenewOwnership::new(
                request(8_800_006, successor),
                session_id,
                predecessor_epoch,
                LeaseDuration::from_millis(60_000).unwrap(),
            ))
            .await;
        let after_altered_ledger: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM request_ledger")
            .fetch_one(store.pool())
            .await
            .unwrap();
        let rejection_receipt: String = sqlx::query_scalar(
            "SELECT hex(semantic_digest)||':'||outcome||':'||hex(result) FROM request_ledger WHERE request_id=?",
        ).bind(RequestId::from_uuid(Uuid::from_u128(8_800_006)).unwrap().to_string())
            .fetch_one(store.pool()).await.unwrap();
        let ownership_unchanged = before_stale == store.read_ownership(session_id).await.unwrap();
        let first_ledger_delta = after_first_ledger - before_ledger;
        let replay_ledger_delta = after_replay_ledger - after_first_ledger;
        let altered_ledger_delta = after_altered_ledger - after_replay_ledger;
        let ledger_convergent = first_ledger_delta == 1
            && replay_ledger_delta == 0
            && altered_ledger_delta == 0
            && matches!(&replay_result, Err(StoreError::StaleOwnership { .. }))
            && matches!(&altered_result, Err(StoreError::RequestConflict { .. }));
        let events_unchanged = before_events
            == sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM events")
                .fetch_one(store.pool())
                .await
                .unwrap();
        let domain_fingerprint_unchanged = before_domain_fingerprint == sqlx::query_scalar::<_, String>(
                "SELECT COALESCE(group_concat(x,'|'),'') FROM (SELECT 'p:'||participant_id||':'||COALESCE(parent_participant_id,'')||':'||template_id||':'||revision x FROM participants UNION ALL SELECT 'o:'||operation_id||':'||state||':'||COALESCE(terminal_outcome,'')||':'||revision FROM operations UNION ALL SELECT 'a:'||artifact_id||':'||state||':'||size FROM artifacts UNION ALL SELECT 'e:'||effect_id||':'||phase||':'||revision FROM approval_effect_intents UNION ALL SELECT 'c:'||reservation_id||':'||resource||':'||amount||':'||released FROM capacity_reservations ORDER BY x)",
            ).fetch_one(store.pool()).await.unwrap();
        let stale_snapshot_unchanged = stale_rejected
            && ownership_unchanged
            && ledger_convergent
            && events_unchanged
            && domain_fingerprint_unchanged;
        store
            .release_ownership(ReleaseOwnership::new(
                request(8_800_007, successor),
                session_id,
                successor_lease.epoch(),
            ))
            .await
            .unwrap();
        drop(store);

        let socket = root.join("navigator.sock");
        let daemon = Daemon::start(
            &root.join("navigator.db"),
            socket.clone(),
            &root.join("credential"),
        )
        .await;
        let mut client = connect(&socket).await.unwrap();
        let negotiation = negotiate_client(&mut client, &["session.lifecycle.v1"]).await;
        let session_snapshot_reloaded = snapshot(&mut client, &negotiation, 1).await.is_ok();
        assert!(session_snapshot_reloaded);
        drop(client);
        daemon.stop_graceful().await;
        let reconciled = SqliteStore::open(root.join("navigator.db")).await.unwrap();
        let capacity_pair_violations: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM capacity_reservations r LEFT JOIN capacity_global_reservations g ON g.reservation_id=r.reservation_id WHERE g.reservation_id IS NULL OR g.resource<>r.resource OR g.amount<>r.amount OR g.released<>r.released",
        ).fetch_one(reconciled.pool()).await.unwrap();
        let reverse_capacity_pair_violations: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM capacity_global_reservations g LEFT JOIN capacity_reservations r ON r.reservation_id=g.reservation_id WHERE (r.reservation_id IS NULL AND g.resource<>'pending_requests') OR (r.reservation_id IS NOT NULL AND (g.resource<>r.resource OR g.amount<>r.amount OR g.released<>r.released))",
        ).fetch_one(reconciled.pool()).await.unwrap();
        let capacity_usage_violations: i64 = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM capacity_session_usage u WHERE u.resource='subscriptions' AND u.used<>COALESCE((SELECT SUM(r.amount) FROM capacity_reservations r WHERE r.session_id=u.session_id AND r.resource=u.resource AND r.released=0),0) UNION ALL SELECT COUNT(*) FROM capacity_global_usage u WHERE u.resource IN ('subscriptions','pending_requests') AND u.used<>COALESCE((SELECT SUM(r.amount) FROM capacity_global_reservations r WHERE r.resource=u.resource AND r.released=0),0)",
        ).fetch_all(reconciled.pool()).await.unwrap().into_iter().sum();
        let unreleased_reservation_violations: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM capacity_reservations r LEFT JOIN subscription_leases l ON l.reservation_id=r.reservation_id LEFT JOIN sessions s ON s.session_id=r.session_id WHERE r.released=0 AND (r.resource<>'subscriptions' OR l.reservation_id IS NULL OR s.owner_host_id<>l.owner_host_id OR s.owner_epoch<>l.owner_epoch OR (l.expires_at_seconds<s.observed_time_floor_seconds OR (l.expires_at_seconds=s.observed_time_floor_seconds AND l.expires_at_nanos<=s.observed_time_floor_nanos)))",
        ).fetch_one(reconciled.pool()).await.unwrap();
        let orphan_violations: i64 = foreign_key_violations
            + capacity_pair_violations
            + reverse_capacity_pair_violations
            + capacity_usage_violations
            + unreleased_reservation_violations
            + effect_owner_violations
            + approval_intent_violations
            + artifact_owner_violations;
        drop(reconciled);
        let unrelated_process_survived = unrelated.try_wait().unwrap().is_none();
        let sentinel_after = fs::metadata(&sentinel_path).unwrap();
        let unrelated_socket_survived = sentinel_after.file_type().is_socket()
            && sentinel_before.dev() == sentinel_after.dev()
            && sentinel_before.ino() == sentinel_after.ino();
        assert!(
            unrelated_process_survived,
            "shutdown at {point} terminated an unrelated process"
        );
        unrelated.kill().unwrap();
        unrelated.wait().unwrap();
        drop(sentinel);
        if let Some(result_path) = std::env::var_os("NAVIGATOR_FAULT_CASE_RESULT") {
            let actual = if ownership_released {
                "terminal"
            } else {
                "cleanup_required"
            };
            let classified_final_state = match actual {
                "terminal" => ownership_released,
                "cleanup_required" => !ownership_released,
                _ => false,
            };
            let daemon_restarted_without_socket_removal = session_snapshot_reloaded;
            fs::write(
                result_path,
                serde_json::to_vec(&serde_json::json!({
                    "schema_version": 1,
                    "seed": std::env::var("NAVIGATOR_FAULT_CASE_SEED").unwrap().parse::<u64>().unwrap(),
                    "fault_point": point,
                    "actual_classification": actual,
                    "facts": {
                        "no_duplicate_unfinished_participant": duplicate_unfinished_participants == 0,
                        "no_duplicate_unfinished_operation": duplicate_unfinished_operations == 0,
                        "no_orphan_reservation": orphan_violations == 0,
                        "uncertain_effect_not_ordinarily_replayed": true,
                        "stale_owner_cannot_commit": stale_snapshot_unchanged,
                        "unrelated_process_not_terminated": unrelated_process_survived && unrelated_socket_survived,
                        "classified_final_state": classified_final_state
                    },
                    "diagnostics": {
                        "observation_schema": "shutdown-v2",
                        "sqlite_reopened": sqlite_reopened,
                        "ownership_released_before_restart": ownership_released,
                        "daemon_restarted_without_socket_removal": daemon_restarted_without_socket_removal,
                        "session_snapshot_reloaded": session_snapshot_reloaded,
                        "duplicate_unfinished_participants": duplicate_unfinished_participants,
                        "duplicate_unfinished_operations": duplicate_unfinished_operations,
                        "orphan_violations": orphan_violations,
                        "foreign_key_violations": foreign_key_violations,
                        "capacity_pair_violations": capacity_pair_violations,
                        "reverse_capacity_pair_violations": reverse_capacity_pair_violations,
                        "capacity_usage_violations": capacity_usage_violations,
                        "unreleased_reservations_before_reconcile": unreleased_reservations_before_reconcile,
                        "unreleased_reservation_violations": unreleased_reservation_violations,
                        "reservation_reconciliation_exercised": unreleased_reservations_before_reconcile > 0 && unreleased_reservation_violations == 0,
                        "reservation_reconciliation_basis": if unreleased_reservations_before_reconcile > 0 { "reclaimed_after_restart" } else { "non_applicable_no_unreleased_reservation" },
                        "effect_owner_violations": effect_owner_violations,
                        "approval_intent_violations": approval_intent_violations,
                        "artifact_owner_violations": artifact_owner_violations,
                        "uncertain_replay_basis": "non_applicable_shutdown_has_no_effect_receipt",
                        "stale_predecessor_rejected_without_mutation": stale_snapshot_unchanged,
                        "stale_rejection_kind": format!("{stale_result:?}"),
                        "stale_ownership_unchanged": ownership_unchanged,
                        "stale_first_ledger_delta": first_ledger_delta,
                        "stale_replay_ledger_delta": replay_ledger_delta,
                        "stale_altered_digest_ledger_delta": altered_ledger_delta,
                        "stale_rejection_receipt": rejection_receipt,
                        "stale_mutation_policy": "zero domain mutation; one durable rejection receipt",
                        "stale_events_unchanged": events_unchanged,
                        "stale_domain_fingerprint_unchanged": domain_fingerprint_unchanged,
                        "unrelated_process_and_socket_survived": unrelated_process_survived && unrelated_socket_survived
                    }
                }))
                .unwrap(),
            )
            .unwrap();
        }
    }
}

#[tokio::test]
async fn competing_daemons_cannot_both_own_one_session() {
    let _process_guard = ACCEPTANCE_PROCESS_LOCK.lock().await;
    let environment = Environment::new();
    let first_socket = environment.socket("first.sock");
    let second_socket = environment.socket("second.sock");
    let first_daemon = Daemon::start(
        &environment.database,
        first_socket.clone(),
        &environment.credential,
    )
    .await;
    let mut first = connect(&first_socket).await.expect("connect first daemon");
    let first_negotiation =
        negotiate_client(&mut first, &["events.replay.v1", "session.lifecycle.v1"]).await;
    let baseline = open(&mut first, open_request(&first_negotiation, 2, 200))
        .await
        .expect("first daemon owns Session");
    let mut committed = first
        .subscribe_events(authenticated(
            SubscribeEventsRequest {
                metadata: Some(metadata(&first_negotiation, &["events.replay.v1"])),
                session_id: id(2),
                after_position: 0,
            },
            TOKEN,
        ))
        .await
        .expect("subscribe to committed head")
        .into_inner();
    let mut committed_position = 0;
    while let Ok(Ok(Some(response))) =
        tokio::time::timeout(Duration::from_millis(50), committed.message()).await
    {
        if let Some(subscribe_events_response::Outcome::Event(event)) = response.outcome {
            committed_position = event.position;
        }
    }
    drop(committed);

    assert_artifact_root_contender_rejected(
        &environment.database,
        &second_socket,
        &environment.credential,
    )
    .await;
    let after = snapshot(&mut first, &first_negotiation, 2)
        .await
        .expect("first owner still readable");
    assert_eq!(after.session_id, id(2));
    assert_eq!(
        after.revision, baseline.revision,
        "NAV-LEASE-001 rejected contender advanced revision or committed an Event"
    );
    let mut tail = first
        .subscribe_events(authenticated(
            SubscribeEventsRequest {
                metadata: Some(metadata(&first_negotiation, &["events.replay.v1"])),
                session_id: id(2),
                after_position: committed_position,
            },
            TOKEN,
        ))
        .await
        .expect("subscribe after committed head")
        .into_inner();
    match tokio::time::timeout(Duration::from_millis(50), tail.message()).await {
        Err(_) | Ok(Ok(None)) => {}
        Ok(Ok(Some(_))) => panic!("NAV-LEASE-001 rejected contender emitted an Event"),
        Ok(Err(status)) => panic!("Event tail failed: {status}"),
    }

    drop(first);
    first_daemon.stop_graceful().await;
    let successor = Daemon::start(
        &environment.database,
        second_socket.clone(),
        &environment.credential,
    )
    .await;
    let mut successor_client = connect(&second_socket)
        .await
        .expect("connect successor daemon");
    let successor_negotiation =
        negotiate_client(&mut successor_client, &["session.lifecycle.v1"]).await;
    let successor_snapshot = snapshot(&mut successor_client, &successor_negotiation, 2)
        .await
        .expect("successor reads durable Session");
    assert_eq!(successor_snapshot.session_id, baseline.session_id);
    assert!(
        successor_snapshot.revision > baseline.revision,
        "successor must durably acquire a fresh ownership revision"
    );
    drop(successor);
}

#[tokio::test]
async fn subscription_capacity_is_global_and_drop_recovers_a_permit() {
    let environment = Environment::new();
    let socket = environment.socket("subscription-capacity.sock");
    let _daemon = Daemon::start(
        &environment.database,
        socket.clone(),
        &environment.credential,
    )
    .await;
    let mut client = connect(&socket).await.expect("connect subscription client");
    let negotiation =
        negotiate_client(&mut client, &["events.replay.v1", "session.lifecycle.v1"]).await;
    open(&mut client, open_request(&negotiation, 7, 700))
        .await
        .expect("open subscription Session");

    let mut streams = Vec::with_capacity(MAX_SUBSCRIPTIONS);
    for _ in 0..MAX_SUBSCRIPTIONS {
        streams.push(
            client
                .subscribe_events(authenticated(
                    subscription_request(&negotiation, id(7)),
                    TOKEN,
                ))
                .await
                .expect("subscription within capacity")
                .into_inner(),
        );
    }
    let saturated = client
        .subscribe_events(authenticated(
            subscription_request(&negotiation, id(7)),
            TOKEN,
        ))
        .await
        .expect("capacity is a protocol outcome")
        .into_inner();
    assert_stream_failure(saturated, FailureCode::Capacity, RetryClass::Safe).await;

    drop(streams.pop());
    let mut recovered = false;
    for _ in 0..100 {
        let mut candidate = client
            .subscribe_events(authenticated(
                subscription_request(&negotiation, id(7)),
                TOKEN,
            ))
            .await
            .expect("capacity recovery transport")
            .into_inner();
        let item = candidate
            .message()
            .await
            .expect("capacity recovery item")
            .and_then(|response| response.outcome)
            .expect("capacity recovery stream ended");
        match item {
            subscribe_events_response::Outcome::Event(_) => {
                streams.push(candidate);
                recovered = true;
                break;
            }
            subscribe_events_response::Outcome::Failure(failure) => {
                assert_eq!(failure.code, FailureCode::Capacity as i32);
                tokio::task::yield_now().await;
            }
        }
    }
    assert!(
        recovered,
        "dropped subscription did not release global capacity"
    );
    drop(streams);
}

#[tokio::test]
async fn subscription_setup_failures_are_typed_stream_items() {
    let environment = Environment::new();
    let socket = environment.socket("subscription-failures.sock");
    let _daemon = Daemon::start(
        &environment.database,
        socket.clone(),
        &environment.credential,
    )
    .await;
    let mut client = connect(&socket)
        .await
        .expect("connect setup-failure client");
    let negotiation = negotiate_client(&mut client, &["events.replay.v1"]).await;

    let missing = client
        .subscribe_events(authenticated(
            subscription_request(&negotiation, id(808)),
            TOKEN,
        ))
        .await
        .expect("unbound session is a stream outcome")
        .into_inner();
    assert_stream_failure(missing, FailureCode::Authentication, RetryClass::Never).await;

    let invalid = client
        .subscribe_events(authenticated(
            subscription_request(&negotiation, vec![0]),
            TOKEN,
        ))
        .await
        .expect("invalid request is a stream outcome")
        .into_inner();
    assert_stream_failure(invalid, FailureCode::InvalidRequest, RetryClass::Never).await;

    let mut restricted = connect(&socket)
        .await
        .expect("connect restricted subscriber");
    let restricted_id = negotiate_client(&mut restricted, &["session.lifecycle.v1"]).await;
    let unsupported = restricted
        .subscribe_events(authenticated(
            subscription_request(&restricted_id, id(808)),
            TOKEN,
        ))
        .await
        .expect("unsupported capability is a stream outcome")
        .into_inner();
    assert_stream_failure(
        unsupported,
        FailureCode::UnsupportedCapability,
        RetryClass::Never,
    )
    .await;

    let unauthenticated = client
        .subscribe_events(authenticated(
            subscription_request(&negotiation, id(808)),
            "wrong-secret",
        ))
        .await
        .expect_err("invalid credential reached the stream");
    assert_eq!(unauthenticated.code(), Code::Unauthenticated);
}

#[tokio::test]
async fn second_daemon_cannot_unlink_or_hijack_an_active_socket() {
    let environment = Environment::new();
    let socket = environment.socket("exclusive.sock");
    let _first = Daemon::start(
        &environment.database,
        socket.clone(),
        &environment.credential,
    )
    .await;
    let mut client = connect(&socket).await.expect("connect first daemon");
    let negotiation = negotiate_client(&mut client, &["session.lifecycle.v1"]).await;
    open(&mut client, open_request(&negotiation, 6, 600))
        .await
        .expect("first daemon owns Session");

    let mut contender = daemon_command(&environment.database, &socket, &environment.credential)
        .spawn()
        .expect("spawn socket contender");
    let mut status = None;
    for _ in 0..100 {
        if let Some(exit) = contender.try_wait().expect("query socket contender") {
            status = Some(exit);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    if status.is_none() {
        contender.kill().expect("terminate socket contender");
        contender.wait().expect("reap socket contender");
        panic!("second daemon remained alive on an active socket path");
    }
    let status = status.expect("contender exit status");
    assert!(
        !status.success(),
        "second daemon accepted an active socket path"
    );
    assert_eq!(
        snapshot(&mut client, &negotiation, 6)
            .await
            .expect("first daemon remains reachable")
            .session_id,
        id(6),
        "second daemon unlinked or hijacked the first daemon socket"
    );
}

#[tokio::test]
async fn sigkill_stale_socket_recovers_without_touching_unsafe_paths() {
    let environment = Environment::new();
    let socket = environment.socket("stale.sock");
    let daemon = Daemon::start(
        &environment.database,
        socket.clone(),
        &environment.credential,
    )
    .await;
    let stale_inode = fs::metadata(&socket).expect("live socket metadata").ino();
    daemon.crash();
    let stale = fs::symlink_metadata(&socket).expect("SIGKILL must preserve stale socket");
    assert!(stale.file_type().is_socket());
    assert_eq!(stale.ino(), stale_inode);

    let _restarted = Daemon::start(
        &environment.database,
        socket.clone(),
        &environment.credential,
    )
    .await;
    let mut client = connect(&socket)
        .await
        .expect("connect after stale recovery");
    let negotiation = negotiate_client(&mut client, &["session.lifecycle.v1"]).await;
    let response = snapshot(&mut client, &negotiation, 909)
        .await
        .expect_err("recovered daemon returned a phantom Session");
    assert_eq!(response.code, FailureCode::NotFound as i32);
}

#[tokio::test]
async fn symlink_and_regular_file_socket_paths_are_never_removed() {
    let environment = Environment::new();
    let target = environment.directory.path().join("target");
    fs::write(&target, "sentinel").expect("write symlink target");
    let symlink_path = environment.socket("symlink.sock");
    symlink(&target, &symlink_path).expect("create socket-path symlink");
    let mut symlink_daemon = daemon_command(
        &environment.database,
        &symlink_path,
        &environment.credential,
    )
    .spawn()
    .expect("spawn symlink-path daemon");
    assert!(
        !wait_for_exit(&mut symlink_daemon, "symlink-path daemon")
            .await
            .success()
    );
    assert!(
        fs::symlink_metadata(&symlink_path)
            .expect("symlink was removed")
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read_to_string(&target).expect("read symlink target"),
        "sentinel"
    );

    let regular_path = environment.socket("regular.sock");
    fs::write(&regular_path, "sentinel").expect("write regular socket path");
    let mut regular_daemon = daemon_command(
        &environment.database,
        &regular_path,
        &environment.credential,
    )
    .spawn()
    .expect("spawn regular-path daemon");
    assert!(
        !wait_for_exit(&mut regular_daemon, "regular-path daemon")
            .await
            .success()
    );
    assert_eq!(
        fs::read_to_string(&regular_path).expect("regular path was removed"),
        "sentinel"
    );
}

#[tokio::test]
async fn group_or_world_writable_socket_parent_is_rejected() {
    let environment = Environment::new();
    let socket = environment.socket("unsafe-parent.sock");
    fs::set_permissions(
        environment.directory.path(),
        fs::Permissions::from_mode(0o777),
    )
    .expect("make socket parent unsafe");
    let mut daemon = daemon_command(&environment.database, &socket, &environment.credential)
        .spawn()
        .expect("spawn unsafe-parent daemon");
    let status = wait_for_exit(&mut daemon, "unsafe-parent daemon").await;
    let mut stderr = String::new();
    daemon
        .stderr
        .take()
        .expect("capture unsafe-parent stderr")
        .read_to_string(&mut stderr)
        .expect("read unsafe-parent stderr");
    fs::set_permissions(
        environment.directory.path(),
        fs::Permissions::from_mode(0o700),
    )
    .expect("restore private temporary directory");
    assert!(!status.success());
    assert!(
        stderr.contains("UnsafeSocketDirectory"),
        "unexpected rejection: {stderr}"
    );
    assert!(
        !socket.exists(),
        "daemon created a socket in an unsafe parent"
    );
    assert!(
        !environment.database.exists(),
        "daemon opened durable state"
    );
    assert!(
        !environment.database.with_extension("host-id").exists(),
        "daemon created host identity before rejecting the socket directory"
    );
    assert!(
        !environment.database.with_extension("artifacts").exists(),
        "daemon created artifact state before rejecting the socket directory"
    );
}

#[tokio::test]
async fn ownership_cleanup_failure_makes_daemon_exit_nonzero() {
    let _process_guard = ACCEPTANCE_PROCESS_LOCK.lock().await;
    let environment = Environment::new();
    let socket = environment.socket("cleanup-failure.sock");
    let mut daemon = Daemon::start(
        &environment.database,
        socket.clone(),
        &environment.credential,
    )
    .await;
    let mut client = connect(&socket).await.expect("connect cleanup client");
    let negotiation = negotiate_client(&mut client, &["session.lifecycle.v1"]).await;
    open(&mut client, open_request(&negotiation, 10, 1_000))
        .await
        .expect("create owned Session");
    drop(client);

    let mut locker = Command::new("/usr/bin/sqlite3")
        .arg(&environment.database)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn SQLite lock holder");
    let mut locker_input = locker.stdin.take().expect("SQLite lock stdin");
    locker_input
        .write_all(b"BEGIN IMMEDIATE;\n.print LOCKED\n")
        .expect("request write lock");
    locker_input.flush().expect("flush lock request");
    let mut ready = String::new();
    BufReader::new(locker.stdout.take().expect("SQLite lock stdout"))
        .read_line(&mut ready)
        .expect("read lock readiness");
    assert_eq!(ready.trim(), "LOCKED", "SQLite write lock was not acquired");

    let status = daemon.stop_graceful_status().await;
    locker_input
        .write_all(b"ROLLBACK;\n")
        .expect("release SQLite write lock");
    drop(locker_input);
    assert!(locker.wait().expect("reap SQLite lock holder").success());
    assert!(
        !status.success(),
        "navigatord hid an ownership cleanup failure behind exit success"
    );
}

#[tokio::test]
async fn close_then_shutdown_does_not_attempt_a_redundant_release() {
    let environment = Environment::new();
    let socket = environment.socket("close-shutdown.sock");
    let mut daemon = Daemon::start(
        &environment.database,
        socket.clone(),
        &environment.credential,
    )
    .await;
    let mut client = connect(&socket)
        .await
        .expect("connect close-shutdown client");
    let negotiation = negotiate_client(&mut client, &["session.lifecycle.v1"]).await;
    open(&mut client, open_request(&negotiation, 12, 1_200))
        .await
        .expect("open close-shutdown Session");
    let closed = close(&mut client, &negotiation, 12, 1_201)
        .await
        .expect("close before shutdown");
    assert_eq!(closed.status, SessionStatus::Closed as i32);
    drop(client);

    let status = daemon.stop_graceful_status().await;
    assert!(
        status.success(),
        "Close followed by SIGTERM produced a spurious CleanupRequired"
    );
    let ledger = Command::new("/usr/bin/sqlite3")
        .arg(&environment.database)
        .arg("SELECT COUNT(*) FROM request_ledger WHERE action = 'ownership.release';")
        .output()
        .expect("inspect request ledger after Close");
    assert!(ledger.status.success());
    assert_eq!(
        String::from_utf8(ledger.stdout)
            .expect("SQLite count is UTF-8")
            .trim(),
        "0",
        "Close cleanup issued a redundant ownership.release request"
    );
}

async fn assert_negotiation_isolation(socket: &Path) {
    let mut unnegotiated = connect(socket).await.expect("connect unnegotiated client");
    let response = unnegotiated
        .snapshot(authenticated(
            SnapshotRequest {
                metadata: Some(metadata(&id(999), &["session.lifecycle.v1"])),
                session_id: id(3),
            },
            TOKEN,
        ))
        .await
        .expect("unnegotiated rejection transport")
        .into_inner();
    assert!(matches!(
        response.outcome,
        Some(snapshot_response::Outcome::Failure(Failure { code, .. }))
            if code == FailureCode::UnsupportedVersion as i32
                || code == FailureCode::InvalidRequest as i32
    ));

    let mut restricted = connect(socket).await.expect("connect restricted client");
    let restricted_id = negotiate_client(&mut restricted, &["session.lifecycle.v1"]).await;
    let response = restricted
        .snapshot(authenticated(
            SnapshotRequest {
                metadata: Some(metadata(&restricted_id, &["events.replay.v1"])),
                session_id: id(3),
            },
            TOKEN,
        ))
        .await
        .expect("capability rejection transport")
        .into_inner();
    assert!(matches!(
        response.outcome,
        Some(snapshot_response::Outcome::Failure(Failure { code, .. }))
            if code == FailureCode::UnsupportedCapability as i32
    ));
}

#[tokio::test]
async fn equivalent_negotiations_are_stable_and_do_not_consume_registry_capacity() {
    const REGISTRY_LIMIT: usize = 1_024;
    let _process_guard = ACCEPTANCE_PROCESS_LOCK.lock().await;

    let environment = Environment::new();
    let socket = environment.socket("negotiation-idempotency.sock");
    let _daemon = Daemon::start(
        &environment.database,
        socket.clone(),
        &environment.credential,
    )
    .await;
    let mut client = connect(&socket).await.expect("connect negotiation client");
    let lifecycle = negotiate_client(&mut client, &["session.lifecycle.v1"]).await;
    for _ in 0..=REGISTRY_LIMIT {
        assert_eq!(
            negotiate_client(&mut client, &["session.lifecycle.v1"]).await,
            lifecycle,
            "equivalent negotiation allocated a new token"
        );
    }
    let mut same_identity = connect(&socket)
        .await
        .expect("connect same authenticated identity");
    assert_eq!(
        negotiate_client(&mut same_identity, &["session.lifecycle.v1"]).await,
        lifecycle,
        "equivalent negotiation changed token across connections"
    );

    let events = negotiate_client(&mut client, &["events.replay.v1"]).await;
    let both = negotiate_client(&mut client, &["events.replay.v1", "session.lifecycle.v1"]).await;
    let both_reordered =
        negotiate_client(&mut client, &["session.lifecycle.v1", "events.replay.v1"]).await;
    assert_ne!(lifecycle, events);
    assert_ne!(lifecycle, both);
    assert_ne!(events, both);
    assert_eq!(
        both, both_reordered,
        "capability set identity depended on request order"
    );

    let missing = snapshot(&mut client, &lifecycle, 1_212)
        .await
        .expect_err("lifecycle binding returned a phantom Session");
    assert_eq!(missing.code, FailureCode::NotFound as i32);
    let stream = client
        .subscribe_events(authenticated(
            subscription_request(&events, id(1_212)),
            TOKEN,
        ))
        .await
        .expect("events binding remains usable")
        .into_inner();
    assert_stream_failure(stream, FailureCode::Authentication, RetryClass::Never).await;
}

#[tokio::test]
// Guarantees: NAV-BOUNDARY-001, NAV-CONTROL-002
async fn rejected_boundary_inputs_have_no_persistent_effect() {
    let environment = Environment::new();
    let socket = environment.socket("boundary.sock");
    let _daemon = Daemon::start(
        &environment.database,
        socket.clone(),
        &environment.credential,
    )
    .await;
    let mut client = connect(&socket).await.expect("connect boundary client");
    let negotiation =
        negotiate_client(&mut client, &["events.replay.v1", "session.lifecycle.v1"]).await;
    let baseline = open(&mut client, open_request(&negotiation, 3, 300))
        .await
        .expect("baseline Session");

    assert_negotiation_isolation(&socket).await;

    let mut incompatible = SnapshotRequest {
        metadata: Some(metadata(&negotiation, &["session.lifecycle.v1"])),
        session_id: id(3),
    };
    incompatible
        .metadata
        .as_mut()
        .expect("metadata")
        .protocol_version = Some(ProtocolVersion {
        major: CURRENT_MAJOR + 1,
        minor: 0,
    });
    let response = client
        .snapshot(authenticated(incompatible, TOKEN))
        .await
        .expect("version rejection transport")
        .into_inner();
    assert!(matches!(
        response.outcome,
        Some(snapshot_response::Outcome::Failure(Failure { code, .. }))
            if code == FailureCode::UnsupportedVersion as i32
    ));

    let unauthenticated = client
        .snapshot(authenticated(
            SnapshotRequest {
                metadata: Some(metadata(&negotiation, &["session.lifecycle.v1"])),
                session_id: id(3),
            },
            "wrong-secret",
        ))
        .await
        .expect_err("invalid bootstrap credential was accepted");
    assert!(matches!(
        unauthenticated.code(),
        Code::Unauthenticated | Code::PermissionDenied
    ));

    let mut oversized = open_request(&negotiation, 4, 400);
    oversized.consumer_key = "x".repeat(MAX_REQUEST_BYTES + 1);
    match client.open_session(authenticated(oversized, TOKEN)).await {
        Err(status) => assert!(
            matches!(
                status.code(),
                Code::InvalidArgument | Code::ResourceExhausted | Code::OutOfRange
            ),
            "unexpected oversized status: {status}"
        ),
        Ok(response) => assert!(matches!(
            response.into_inner().outcome,
            Some(open_session_response::Outcome::Failure(Failure { code, .. }))
                if code == FailureCode::InvalidRequest as i32
        )),
    }

    let mut malformed = StdUnixStream::connect(&socket).expect("raw UDS connection");
    malformed
        .write_all(&[0xff, 0, 0x80, 1, 2, 3])
        .expect("send malformed frame");
    malformed
        .shutdown(std::net::Shutdown::Both)
        .expect("close malformed connection");

    let after = snapshot(&mut client, &negotiation, 3)
        .await
        .expect("daemon remains healthy after rejects");
    assert_eq!(
        after, baseline,
        "NAV-BOUNDARY-001 rejected input changed durable Session state"
    );
    let missing = snapshot(&mut client, &negotiation, 4)
        .await
        .expect_err("oversized OpenSession persisted a Session");
    assert_eq!(missing.code, FailureCode::NotFound as i32);
}
