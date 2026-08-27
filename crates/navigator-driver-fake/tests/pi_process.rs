#![cfg(unix)]

use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    os::unix::net::{UnixListener, UnixStream},
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use command_fds::{CommandFdExt, FdMapping};
use navigator_conformance::driver::{
    AcceptanceObservation as ContractAcceptance, CapabilityLaunchHarness, CapabilityObservation,
    DriverDescription, DriverErrorKind, DriverSubject, FaultDriverHarness, FaultWindow,
    InstanceBinding as ContractBinding, InstanceObservation as ContractInstance,
    StopObservation as ContractStop, assert_driver_contract, assert_driver_fault_windows,
    assert_durable_acceptance_contract, assert_missing_capability_prevents_launch,
};
use navigator_domain::{
    BoundedText, Capability, DriverCapabilityRequirement, DriverId, DriverRequirement,
    FencingEpoch, HostId, InputSchema, InstanceId, LaunchAttemptId, ParticipantId, RequestId,
    ResourceBounds, SessionId, Template, TemplateId, TrustedConfiguration,
};
use navigator_driver_client::{ClientError, DriverClient, DriverCredential, StartParameters};
use navigator_driver_protocol::{PROTOCOL_V1, authentication_tag, canonical_request_digest, v1};
use navigator_local::{CatalogDriverConfigResolver, DriverConfigResolver, TrustedDriverCatalog};
use navigator_supervisor::{LaunchPlan, ProcessBackend, UnixProcessBackend};
use prost::Message;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

mod common;

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

struct PiHarness {
    directory: Arc<TempDir>,
    socket: PathBuf,
    session_file: PathBuf,
    abort_observer: PathBuf,
    prompt_observer: PathBuf,
    delivery_observer: PathBuf,
    child: Child,
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }

    fn release(mut self) -> Child {
        self.0.take().unwrap()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

const MAX_FAULT_FRAME_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum PiFaultPoint {
    BeforeAppend,
    AfterFsync,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum PiFaultFrame {
    #[serde(rename = "ARM")]
    Arm {
        point: PiFaultPoint,
        #[serde(rename = "messageId")]
        message_id: String,
        #[serde(rename = "deliveryAttemptId")]
        delivery_attempt_id: String,
    },
    #[serde(rename = "REACHED")]
    Reached {
        point: PiFaultPoint,
        #[serde(rename = "messageId")]
        message_id: String,
        #[serde(rename = "deliveryAttemptId")]
        delivery_attempt_id: String,
    },
    #[serde(rename = "RELEASE")]
    Release,
}

pub struct FaultProtocolHarness {
    directory: TempDir,
    private_root: PathBuf,
    journal: PathBuf,
    binding: Option<v1::InstanceIdentity>,
    child: Option<Child>,
    ownership: Option<UnixStream>,
    fault_control: Option<UnixStream>,
}

impl FaultProtocolHarness {
    #[must_use]
    pub fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let private_root = directory.path().join("private-runtime");
        fs::create_dir(&private_root).unwrap();
        fs::set_permissions(&private_root, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            private_root,
            journal: directory.path().join("session.jsonl.navigator-inbox"),
            directory,
            binding: None,
            child: None,
            ownership: None,
            fault_control: None,
        }
    }

    pub fn install_process(
        &mut self,
        child: Child,
        ownership: UnixStream,
        fault_control: UnixStream,
    ) {
        assert!(
            self.child.is_none(),
            "fault child must be reaped before restart"
        );
        self.child = Some(child);
        self.ownership = Some(ownership);
        self.fault_control = Some(fault_control);
    }

    pub fn crash_exact_child(&mut self, deadline: Instant) -> std::io::Result<()> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| std::io::Error::other("fault child missing"))?;
        child.kill()?;
        while child.try_wait()?.is_none() {
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "fault child exit deadline",
                ));
            }
            thread::sleep(Duration::from_millis(1));
        }
        self.child = None;
        self.ownership = None;
        self.fault_control = None;
        Ok(())
    }

    fn read_fault_frame(
        stream: &mut UnixStream,
        deadline: Instant,
    ) -> std::io::Result<PiFaultFrame> {
        let mut bytes = Vec::new();
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "fault frame deadline")
                })?;
            stream.set_read_timeout(Some(remaining))?;
            let mut byte = [0];
            stream.read_exact(&mut byte)?;
            if byte[0] == b'\n' {
                break;
            }
            if bytes.len() == MAX_FAULT_FRAME_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "fault frame exceeds bound",
                ));
            }
            bytes.push(byte[0]);
        }
        let frame: PiFaultFrame = serde_json::from_slice(&bytes)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        if !serde_json::to_vec(&frame).is_ok_and(|encoded| encoded == bytes) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "fault frame is not canonical JSON",
            ));
        }
        validate_fault_frame(&frame)?;
        Ok(frame)
    }

    #[must_use]
    pub fn persistent_paths(&self) -> (&Path, &Path) {
        (&self.private_root, &self.journal)
    }
    #[must_use]
    pub fn directory(&self) -> &Path {
        self.directory.path()
    }
    #[must_use]
    pub fn binding(&self) -> Option<&v1::InstanceIdentity> {
        self.binding.as_ref()
    }
}

impl Default for FaultProtocolHarness {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for FaultProtocolHarness {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn validate_fault_frame(frame: &PiFaultFrame) -> std::io::Result<()> {
    let ids = match frame {
        PiFaultFrame::Arm {
            message_id,
            delivery_attempt_id,
            ..
        }
        | PiFaultFrame::Reached {
            message_id,
            delivery_attempt_id,
            ..
        } => Some((message_id, delivery_attempt_id)),
        PiFaultFrame::Release => None,
    };
    if ids.is_some_and(|(message, attempt)| !is_lower_hex_id(message) || !is_lower_hex_id(attempt))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "fault identity is not exact lower hex",
        ));
    }
    Ok(())
}

fn is_lower_hex_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub struct PiConformanceSubject {
    evidence: PiEvidence,
    _process: Option<PiHarness>,
    client: DriverClient,
    instance: Option<v1::InstanceIdentity>,
    attempts: HashMap<u128, Vec<u8>>,
    expected_deliveries: HashMap<String, ExpectedDelivery>,
    next_request: u128,
    fault_state: Option<Arc<Mutex<PersistentFaultState>>>,
}

struct FaultProcess {
    generation: u64,
    child: Child,
    ownership: Option<UnixStream>,
    fault_cancel: Option<UnixStream>,
    watcher: Option<thread::JoinHandle<()>>,
    outcome: Option<Arc<Mutex<FaultOutcome>>>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
enum FaultOutcome {
    Armed,
    ReachedExact,
    KillSucceeded,
    ReapedBySignal(i32),
    Failed,
}

fn is_completed_crash(outcome: &FaultOutcome) -> bool {
    matches!(outcome, FaultOutcome::ReapedBySignal(9))
}
struct PersistentFaultState {
    directory: Arc<TempDir>,
    generation: u64,
    process: Option<FaultProcess>,
    binding: Option<v1::InstanceIdentity>,
    attempts: HashMap<u128, Vec<u8>>,
    expected_deliveries: HashMap<String, ExpectedDelivery>,
}
pub struct PiFaultHarness {
    state: Arc<Mutex<PersistentFaultState>>,
}

struct FaultRuntime {
    socket: PathBuf,
    credential: PathBuf,
    bootstrap: PathBuf,
    evidence: PiEvidence,
}

fn prepare_fault_runtime(
    directory: Arc<TempDir>,
    has_fault: bool,
) -> Result<FaultRuntime, DriverErrorKind> {
    let socket = directory.path().join("control.sock");
    let credential = directory.path().join("credential");
    let provider = directory.path().join("provider.mjs");
    let _ = fs::remove_file(&socket);
    fs::write(&credential, SECRET).map_err(|_| DriverErrorKind::Unavailable)?;
    fs::set_permissions(&credential, fs::Permissions::from_mode(0o600))
        .map_err(|_| DriverErrorKind::Unavailable)?;
    fs::write(&provider, faux_provider_module()).map_err(|_| DriverErrorKind::Unavailable)?;
    let bootstrap = directory.path().join("fault-bootstrap.json");
    let mut value = serde_json::json!({
        "provider":"faux", "model":"faux-1", "authPath":directory.path().join("auth.json"),
        "providerModule":provider, "abortObserverPath":"native-aborts.log",
        "promptObserverPath":"native-prompts.log", "deliveryObserverPath":"native-deliveries.log",
        "cwd":directory.path(), "tools":[],
    });
    if has_fault {
        value["journalFaultFd"] = serde_json::json!(4);
    }
    fs::write(&bootstrap, serde_json::to_vec(&value).unwrap())
        .map_err(|_| DriverErrorKind::Unavailable)?;
    fs::set_permissions(&bootstrap, fs::Permissions::from_mode(0o600))
        .map_err(|_| DriverErrorKind::Unavailable)?;
    let evidence = PiEvidence {
        abort_observer: directory.path().join("native-aborts.log"),
        prompt_observer: directory.path().join("native-prompts.log"),
        delivery_observer: directory.path().join("native-deliveries.log"),
        directory,
    };
    Ok(FaultRuntime {
        socket,
        credential,
        bootstrap,
        evidence,
    })
}

fn fault_target(fault: FaultWindow) -> Option<(PiFaultFrame, PiFaultFrame)> {
    let (point, message) = match fault {
        FaultWindow::CrashBeforeAcceptance => (PiFaultPoint::BeforeAppend, 31),
        FaultWindow::CrashAfterDurableAcceptance => (PiFaultPoint::AfterFsync, 32),
        FaultWindow::CrashAfterVolatileReceipt => (PiFaultPoint::BeforeAppend, 33),
        FaultWindow::None => return None,
    };
    let message_id = bytes_hex(&PiConformanceSubject::derived_bytes(
        b"conformance.message",
        message,
    ));
    let delivery_attempt_id = bytes_hex(&PiConformanceSubject::derived_bytes(
        b"conformance.delivery-attempt",
        message,
    ));
    Some((
        PiFaultFrame::Arm {
            point,
            message_id: message_id.clone(),
            delivery_attempt_id: delivery_attempt_id.clone(),
        },
        PiFaultFrame::Reached {
            point,
            message_id,
            delivery_attempt_id,
        },
    ))
}

fn spawn_fault_child(
    runtime: &FaultRuntime,
    private_root: &Path,
    child_owner: UnixStream,
    child_fault: Option<UnixStream>,
) -> Result<Child, DriverErrorKind> {
    let mut command = Command::new("node");
    command
        .arg("--preserve-symlinks")
        .arg("dist/main.js")
        .current_dir(built_pi_package())
        .env("NAVIGATOR_CONTROL_SOCKET", &runtime.socket)
        .env("NAVIGATOR_CREDENTIAL_FILE", &runtime.credential)
        .env("NAVIGATOR_DRIVER_ID", "01010101010101010101010101010101")
        .env("NAVIGATOR_DRIVER_BOOTSTRAP_FILE", &runtime.bootstrap)
        .env("NAVIGATOR_DRIVER_PRIVATE_ROOT", private_root)
        .env("NAVIGATOR_OWNERSHIP_FD", "3")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let mut mappings = vec![FdMapping {
        parent_fd: child_owner.into(),
        child_fd: 3,
    }];
    if let Some(child_fault) = child_fault {
        mappings.push(FdMapping {
            parent_fd: child_fault.into(),
            child_fd: 4,
        });
    }
    command
        .fd_mappings(mappings)
        .map_err(|_| DriverErrorKind::Unavailable)?;
    command.spawn().map_err(|_| DriverErrorKind::Unavailable)
}

fn install_fault_watcher(
    state: &Arc<Mutex<PersistentFaultState>>,
    mut control: UnixStream,
    expected: PiFaultFrame,
    generation: u64,
    outcome: Arc<Mutex<FaultOutcome>>,
    completion: Option<std::sync::mpsc::SyncSender<()>>,
) -> Result<(), DriverErrorKind> {
    let mut process_guard = state.lock().map_err(|_| DriverErrorKind::Unavailable)?;
    if !matches!(
        process_guard.process.as_ref(),
        Some(process) if process.generation == generation
    ) {
        return Err(DriverErrorKind::Conflict);
    }
    let shared = state.clone();
    let watcher = thread::spawn(move || {
        let mut run = || {
            let reached = FaultProtocolHarness::read_fault_frame(
                &mut control,
                Instant::now() + Duration::from_secs(30),
            );
            if !matches!(reached.as_ref(), Ok(frame) if frame == &expected) {
                if let Ok(mut value) = outcome.lock() {
                    *value = FaultOutcome::Failed;
                }
                return;
            }
            if let Ok(mut value) = outcome.lock() {
                *value = FaultOutcome::ReachedExact;
            }
            let killed = if let Ok(mut state) = shared.lock()
                && let Some(process) = state.process.as_mut()
                && process.generation == generation
            {
                process.child.kill().is_ok()
            } else {
                false
            };
            if !killed {
                if let Ok(mut value) = outcome.lock() {
                    *value = FaultOutcome::Failed;
                }
                return;
            }
            if let Ok(mut value) = outcome.lock() {
                *value = FaultOutcome::KillSucceeded;
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                let status = if let Ok(mut state) = shared.lock()
                    && let Some(process) = state.process.as_mut()
                    && process.generation == generation
                {
                    process.child.try_wait()
                } else {
                    if let Ok(mut value) = outcome.lock() {
                        *value = FaultOutcome::Failed;
                    }
                    return;
                };
                match status {
                    Ok(Some(status)) => {
                        if let Ok(mut value) = outcome.lock() {
                            *value = match status.signal() {
                                Some(signal) => FaultOutcome::ReapedBySignal(signal),
                                None => FaultOutcome::Failed,
                            };
                        }
                        return;
                    }
                    Ok(None) if Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    _ => {
                        if let Ok(mut value) = outcome.lock() {
                            *value = FaultOutcome::Failed;
                        }
                        return;
                    }
                }
            }
        };
        run();
        if let Some(completion) = completion {
            let _ = completion.send(());
        }
    });
    process_guard
        .process
        .as_mut()
        .expect("fault process was validated while holding its state lock")
        .watcher = Some(watcher);
    Ok(())
}

impl Drop for PersistentFaultState {
    fn drop(&mut self) {
        if let Some(process) = self.process.as_mut() {
            if let Some(cancel) = process.fault_cancel.take() {
                let _ = cancel.shutdown(std::net::Shutdown::Both);
            }
            let _ = process.child.kill();
            let _ = process.child.wait();
            if let Some(watcher) = process.watcher.take() {
                let _ = watcher.join();
            }
        }
    }
}

#[derive(Clone)]
struct PiEvidence {
    directory: Arc<TempDir>,
    abort_observer: PathBuf,
    prompt_observer: PathBuf,
    delivery_observer: PathBuf,
}

#[derive(Clone, Eq, PartialEq)]
struct ExpectedDelivery {
    operation_id: String,
    delivery_attempt_id: String,
    prompt_digest: String,
}

struct JournalDeliveryIdentities {
    binding: serde_json::Value,
    pending: HashMap<String, (String, String)>,
    delivered: HashSet<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeDeliveryObservation {
    message_id: String,
    delivery_attempt_id: String,
    sha256: String,
}

struct PiCapabilityLaunchHarness {
    _directory: TempDir,
    resolver: CatalogDriverConfigResolver,
    driver_id: DriverId,
    backend: UnixProcessBackend,
    spawn_calls: Arc<AtomicU64>,
}

impl PiHarness {
    fn spawn() -> Self {
        let directory = Arc::new(tempfile::tempdir().unwrap());
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let credential = directory.path().join("credential");
        let socket = directory.path().join("control.sock");
        let session_file = session_file(directory.path());
        let abort_observer = directory.path().join("native-aborts.log");
        let prompt_observer = directory.path().join("native-prompts.log");
        let delivery_observer = directory.path().join("native-deliveries.log");
        let provider = directory.path().join("provider.mjs");
        fs::write(&credential, SECRET).unwrap();
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&provider, faux_provider_module()).unwrap();

        let package = built_pi_package();
        let bootstrap = runtime_bootstrap(directory.path(), &provider);
        let child = Command::new("/bin/sh")
            .args([
                "-c",
                "exec 3<&0; exec 0</dev/null; exec node --preserve-symlinks dist/main.js",
            ])
            .current_dir(package)
            .env("NAVIGATOR_CONTROL_SOCKET", &socket)
            .env("NAVIGATOR_CREDENTIAL_FILE", credential)
            .env("NAVIGATOR_DRIVER_ID", "01010101010101010101010101010101")
            .env("NAVIGATOR_DRIVER_BOOTSTRAP_FILE", bootstrap)
            .env("NAVIGATOR_DRIVER_PRIVATE_ROOT", directory.path())
            .env("NAVIGATOR_OWNERSHIP_FD", "3")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let child = ChildGuard::new(child);
        let deadline = Instant::now() + Duration::from_secs(8);
        while match fs::symlink_metadata(&socket) {
            Ok(metadata) => metadata.permissions().mode() & 0o777 != 0o600,
            Err(_) => true,
        } {
            assert!(
                Instant::now() < deadline,
                "Pi Driver did not publish a private UDS"
            );
            thread::sleep(Duration::from_millis(10));
        }
        Self {
            directory,
            socket,
            session_file,
            abort_observer,
            prompt_observer,
            delivery_observer,
            child: child.release(),
        }
    }

    fn client(&self, secret: &[u8]) -> Result<DriverClient, ClientError> {
        DriverClient::connect(
            &self.socket,
            DriverCredential::new(secret.to_vec()).unwrap(),
            Duration::from_secs(3),
        )
    }
}

impl PiFaultHarness {
    fn new() -> Self {
        let directory = Arc::new(tempfile::tempdir().unwrap());
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            state: Arc::new(Mutex::new(PersistentFaultState {
                directory,
                generation: 0,
                process: None,
                binding: None,
                attempts: HashMap::new(),
                expected_deliveries: HashMap::new(),
            })),
        }
    }

    fn stop_current(&self) -> Result<(), DriverErrorKind> {
        let process = self
            .state
            .lock()
            .map_err(|_| DriverErrorKind::Unavailable)?
            .process
            .take();
        if let Some(mut process) = process {
            if let Some(cancel) = process.fault_cancel.take() {
                let _ = cancel.shutdown(std::net::Shutdown::Both);
            }
            match process.child.try_wait() {
                Ok(Some(_)) => {}
                Ok(None) => {
                    process
                        .child
                        .kill()
                        .map_err(|_| DriverErrorKind::Unavailable)?;
                    process
                        .child
                        .wait()
                        .map_err(|_| DriverErrorKind::Unavailable)?;
                }
                Err(_) => return Err(DriverErrorKind::Unavailable),
            }
            if process
                .watcher
                .take()
                .is_some_and(|watcher| watcher.join().is_err())
            {
                return Err(DriverErrorKind::Unavailable);
            }
        }
        Ok(())
    }

    fn begin_generation(&self) -> Result<(Arc<TempDir>, u64), DriverErrorKind> {
        let prior = self
            .state
            .lock()
            .map_err(|_| DriverErrorKind::Unavailable)?
            .process
            .as_ref()
            .and_then(|process| process.outcome.clone());
        if let Some(outcome) = prior
            && !matches!(
                *outcome.lock().map_err(|_| DriverErrorKind::Unavailable)?,
                FaultOutcome::ReapedBySignal(9)
            )
        {
            return Err(DriverErrorKind::Conflict);
        }
        self.stop_current()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| DriverErrorKind::Unavailable)?;
        state.generation += 1;
        Ok((state.directory.clone(), state.generation))
    }

    fn commit_durable_expected(&self) -> Result<(), DriverErrorKind> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DriverErrorKind::Unavailable)?;
        state.expected_deliveries.insert(
            bytes_hex(&PiConformanceSubject::derived_bytes(
                b"conformance.message",
                32,
            )),
            ExpectedDelivery {
                operation_id: bytes_hex(&PiConformanceSubject::derived_bytes(
                    b"conformance.operation",
                    42,
                )),
                delivery_attempt_id: bytes_hex(&PiConformanceSubject::derived_bytes(
                    b"conformance.delivery-attempt",
                    32,
                )),
                prompt_digest: file_digest_bytes(b"after"),
            },
        );
        Ok(())
    }

    fn spawn_subject(&self, fault: FaultWindow) -> Result<PiConformanceSubject, DriverErrorKind> {
        let (directory, generation) = self.begin_generation()?;
        let has_fault = fault != FaultWindow::None;
        let runtime = prepare_fault_runtime(directory.clone(), has_fault)?;
        let socket = runtime.socket.clone();

        let (owner, child_owner) = UnixStream::pair().map_err(|_| DriverErrorKind::Unavailable)?;
        let (mut fault_parent, child_fault) = if has_fault {
            let pair = UnixStream::pair().map_err(|_| DriverErrorKind::Unavailable)?;
            (Some(pair.0), Some(pair.1))
        } else {
            (None, None)
        };
        let target = fault_target(fault);
        let expected = if let Some((arm, expected)) = target {
            let mut encoded = serde_json::to_vec(&arm).unwrap();
            encoded.push(b'\n');
            fault_parent
                .as_mut()
                .unwrap()
                .write_all(&encoded)
                .map_err(|_| DriverErrorKind::Unavailable)?;
            Some(expected)
        } else {
            None
        };
        let child = spawn_fault_child(&runtime, directory.path(), child_owner, child_fault)?;
        let fault_cancel = fault_parent
            .as_ref()
            .and_then(|stream| stream.try_clone().ok());
        let outcome = has_fault.then(|| Arc::new(Mutex::new(FaultOutcome::Armed)));
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| DriverErrorKind::Unavailable)?;
            state.process = Some(FaultProcess {
                generation,
                child,
                ownership: Some(owner),
                fault_cancel,
                watcher: None,
                outcome: outcome.clone(),
            });
        }

        if let Some(control) = fault_parent {
            install_fault_watcher(
                &self.state,
                control,
                expected.unwrap(),
                generation,
                outcome.unwrap(),
                None,
            )?;
        }
        if fault == FaultWindow::CrashAfterDurableAcceptance {
            self.commit_durable_expected()?;
        }

        let deadline = Instant::now() + Duration::from_secs(8);
        while UnixStream::connect(&socket).is_err() {
            if Instant::now() >= deadline {
                return Err(DriverErrorKind::Unavailable);
            }
            thread::sleep(Duration::from_millis(10));
        }
        let client = DriverClient::connect(
            &socket,
            DriverCredential::new(SECRET.to_vec()).unwrap(),
            Duration::from_secs(3),
        )
        .map_err(PiConformanceSubject::error)?;
        let (attempts, expected_deliveries) = {
            let state = self
                .state
                .lock()
                .map_err(|_| DriverErrorKind::Unavailable)?;
            (state.attempts.clone(), state.expected_deliveries.clone())
        };
        Ok(PiConformanceSubject {
            evidence: runtime.evidence,
            _process: None,
            client,
            instance: None,
            attempts,
            expected_deliveries,
            next_request: 1_000,
            fault_state: Some(self.state.clone()),
        })
    }
}

impl FaultDriverHarness for PiFaultHarness {
    type Subject = PiConformanceSubject;

    async fn launch(&mut self, fault: FaultWindow) -> Result<Self::Subject, DriverErrorKind> {
        self.spawn_subject(fault)
    }

    async fn restart(&mut self, fault: FaultWindow) -> Result<Self::Subject, DriverErrorKind> {
        let expected = self
            .state
            .lock()
            .map_err(|_| DriverErrorKind::Unavailable)?
            .binding
            .clone()
            .ok_or(DriverErrorKind::Conflict)?;
        let mut subject = self.spawn_subject(fault)?;
        let actual = subject.start(10, 21, 5, 1, Vec::new()).await;
        let actual = actual?;
        if actual != PiConformanceSubject::binding(&expected) {
            return Err(DriverErrorKind::Conflict);
        }
        Ok(subject)
    }

    async fn disconnect_owner(&mut self) -> Result<(), DriverErrorKind> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DriverErrorKind::Unavailable)?;
        let process = state.process.as_mut().ok_or(DriverErrorKind::Unavailable)?;
        if process.outcome.is_some()
            || process
                .child
                .try_wait()
                .map_err(|_| DriverErrorKind::Unavailable)?
                .is_some()
        {
            return Err(DriverErrorKind::Conflict);
        }
        process.ownership.take().ok_or(DriverErrorKind::Conflict)?;
        Ok(())
    }

    async fn deliver_after_owner_disconnect(
        &mut self,
    ) -> Result<ContractAcceptance, DriverErrorKind> {
        let (directory, binding) = {
            let state = self
                .state
                .lock()
                .map_err(|_| DriverErrorKind::Unavailable)?;
            (
                state.directory.clone(),
                state.binding.clone().ok_or(DriverErrorKind::Conflict)?,
            )
        };
        let client = DriverClient::connect(
            &directory.path().join("control.sock"),
            DriverCredential::new(SECRET.to_vec()).unwrap(),
            Duration::from_secs(1),
        );
        let result = match client {
            Ok(client) => {
                let mut subject = PiConformanceSubject {
                    evidence: PiEvidence {
                        directory: directory.clone(),
                        abort_observer: directory.path().join("native-aborts.log"),
                        prompt_observer: directory.path().join("native-prompts.log"),
                        delivery_observer: directory.path().join("native-deliveries.log"),
                    },
                    _process: None,
                    client,
                    instance: Some(binding.clone()),
                    attempts: HashMap::new(),
                    expected_deliveries: HashMap::new(),
                    next_request: 2_000,
                    fault_state: Some(self.state.clone()),
                };
                subject
                    .deliver(
                        PiConformanceSubject::binding(&binding),
                        99,
                        109,
                        b"orphan".to_vec(),
                    )
                    .await
            }
            Err(error) => Err(PiConformanceSubject::error(error)),
        };
        let exited = self.wait_for_exit_within(1_000).await?;
        let message = bytes_hex(&PiConformanceSubject::derived_bytes(
            b"conformance.message",
            99,
        ));
        let absent = ownership_identity_absent(directory.path(), &message)?;
        if exited && absent && result.is_err() {
            Err(DriverErrorKind::Unavailable)
        } else {
            Err(DriverErrorKind::Conflict)
        }
    }

    async fn wait_for_exit_within(&mut self, milliseconds: u64) -> Result<bool, DriverErrorKind> {
        let deadline = Instant::now() + Duration::from_millis(milliseconds);
        loop {
            let exited = {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| DriverErrorKind::Unavailable)?;
                let process = state.process.as_mut().ok_or(DriverErrorKind::Unavailable)?;
                process
                    .child
                    .try_wait()
                    .map_err(|_| DriverErrorKind::Unavailable)?
                    .is_some()
            };
            if exited {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}

impl PiConformanceSubject {
    fn spawn() -> Self {
        let harness = PiHarness::spawn();
        let client = harness.client(SECRET).unwrap();
        let evidence = PiEvidence {
            directory: harness.directory.clone(),
            abort_observer: harness.abort_observer.clone(),
            prompt_observer: harness.prompt_observer.clone(),
            delivery_observer: harness.delivery_observer.clone(),
        };
        Self {
            evidence,
            _process: Some(harness),
            client,
            instance: None,
            attempts: HashMap::new(),
            expected_deliveries: HashMap::new(),
            next_request: 1_000,
            fault_state: None,
        }
    }

    fn request(&mut self) -> Vec<u8> {
        let value = self.next_request;
        self.next_request += 1;
        Self::bytes(value)
    }

    fn bytes(value: u128) -> Vec<u8> {
        value.to_be_bytes().to_vec()
    }

    fn derived_bytes(domain: &[u8], value: u128) -> Vec<u8> {
        let digest = Sha256::new()
            .chain_update(domain)
            .chain_update(value.to_be_bytes())
            .finalize();
        let mut bytes: [u8; 16] = digest[..16].try_into().unwrap();
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        bytes.to_vec()
    }

    fn binding(instance: &v1::InstanceIdentity) -> ContractBinding {
        let value = |bytes: &[u8]| u128::from_be_bytes(bytes.try_into().unwrap());
        ContractBinding {
            driver: value(&instance.driver_id),
            session: value(&instance.session_id),
            participant: value(&instance.participant_id),
            launch_attempt: value(&instance.launch_attempt_id),
            instance: value(&instance.instance_id),
            ownership_epoch: instance.ownership_epoch,
        }
    }

    fn protocol_instance(binding: ContractBinding) -> v1::InstanceIdentity {
        v1::InstanceIdentity {
            driver_id: Self::bytes(binding.driver),
            session_id: Self::bytes(binding.session),
            participant_id: Self::bytes(binding.participant),
            launch_attempt_id: Self::bytes(binding.launch_attempt),
            instance_id: Self::bytes(binding.instance),
            ownership_epoch: binding.ownership_epoch,
        }
    }

    fn error(error: ClientError) -> DriverErrorKind {
        match error {
            ClientError::Credential => DriverErrorKind::Authentication,
            ClientError::Io(_) => DriverErrorKind::Unavailable,
            ClientError::Protocol | ClientError::ProtocolDetail(_) | ClientError::Correlation => {
                DriverErrorKind::Conflict
            }
            ClientError::Failure(failure) => match v1::FailureCode::try_from(failure.code) {
                Ok(v1::FailureCode::Authentication | v1::FailureCode::Authorization) => {
                    DriverErrorKind::Authentication
                }
                Ok(v1::FailureCode::Unsupported | v1::FailureCode::Incompatible) => {
                    DriverErrorKind::Unsupported
                }
                Ok(
                    v1::FailureCode::Timeout
                    | v1::FailureCode::Unavailable
                    | v1::FailureCode::CleanupRequired
                    | v1::FailureCode::Internal,
                ) => DriverErrorKind::Unavailable,
                _ => DriverErrorKind::Conflict,
            },
        }
    }

    fn completed_fault(&self) -> bool {
        let outcome = self
            .fault_state
            .as_ref()
            .and_then(|state| state.lock().ok()?.process.as_ref()?.outcome.clone());
        let Some(outcome) = outcome else { return false };
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if outcome.lock().is_ok_and(|value| is_completed_crash(&value)) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn journal_delivery_identities(&self) -> Result<JournalDeliveryIdentities, DriverErrorKind> {
        let paths = fs::read_dir(self.evidence.directory.path())
            .map_err(|_| DriverErrorKind::Unavailable)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.to_string_lossy().ends_with(".navigator-inbox"))
            .collect::<Vec<_>>();
        let [path] = paths.as_slice() else {
            return if paths.is_empty() {
                Err(DriverErrorKind::Unavailable)
            } else {
                Err(DriverErrorKind::Conflict)
            };
        };
        let journal = parse_delivery_journal(
            &fs::read_to_string(path).map_err(|_| DriverErrorKind::Unavailable)?,
        )?;
        if self.instance.as_ref().is_some_and(|instance| {
            journal.binding["driverId"] != bytes_hex(&instance.driver_id)
                || journal.binding["sessionId"] != bytes_hex(&instance.session_id)
                || journal.binding["participantId"] != bytes_hex(&instance.participant_id)
                || journal.binding["launchAttemptId"] != bytes_hex(&instance.launch_attempt_id)
                || journal.binding["instanceId"] != bytes_hex(&instance.instance_id)
                || journal.binding["ownershipEpoch"] != format!("{}n", instance.ownership_epoch)
        }) {
            return Err(DriverErrorKind::Conflict);
        }
        Ok(journal)
    }

    fn prompt_observations(&self) -> Result<Vec<String>, DriverErrorKind> {
        let contents = match fs::read_to_string(&self.evidence.prompt_observer) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(DriverErrorKind::Unavailable),
        };
        let observations = contents.lines().map(str::to_owned).collect::<Vec<_>>();
        if observations.iter().any(|digest| {
            digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        }) {
            return Err(DriverErrorKind::Conflict);
        }
        Ok(observations)
    }

    fn abort_count(&self) -> Result<u64, DriverErrorKind> {
        let contents = match fs::read_to_string(&self.evidence.abort_observer) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(_) => return Err(DriverErrorKind::Unavailable),
        };
        if contents.lines().any(|line| line != "abort") {
            return Err(DriverErrorKind::Conflict);
        }
        contents
            .lines()
            .count()
            .try_into()
            .map_err(|_| DriverErrorKind::Unavailable)
    }

    fn native_delivery_observations(
        &self,
    ) -> Result<HashMap<String, (String, String)>, DriverErrorKind> {
        let contents = fs::read_to_string(&self.evidence.delivery_observer)
            .map_err(|_| DriverErrorKind::Unavailable)?;
        parse_native_delivery_observations(&contents)
    }
}

fn parse_native_delivery_observations(
    contents: &str,
) -> Result<HashMap<String, (String, String)>, DriverErrorKind> {
    let mut observations = HashMap::new();
    for line in contents.lines() {
        let observation = serde_json::from_str::<NativeDeliveryObservation>(line)
            .map_err(|_| DriverErrorKind::Conflict)?;
        if observations
            .insert(
                observation.message_id,
                (observation.delivery_attempt_id, observation.sha256),
            )
            .is_some()
        {
            return Err(DriverErrorKind::Conflict);
        }
    }
    Ok(observations)
}

fn ownership_identity_absent(directory: &Path, message: &str) -> Result<bool, DriverErrorKind> {
    let paths = fs::read_dir(directory)
        .map_err(|_| DriverErrorKind::Unavailable)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.to_string_lossy().ends_with(".navigator-inbox"))
        .collect::<Vec<_>>();
    let mut admitted = false;
    for path in paths {
        let contents = fs::read_to_string(path).map_err(|_| DriverErrorKind::Unavailable)?;
        let journal = parse_delivery_journal(&contents)?;
        admitted |= journal.pending.contains_key(message) || journal.delivered.contains(message);
    }
    let native = match fs::read_to_string(directory.join("native-deliveries.log")) {
        Ok(contents) => parse_native_delivery_observations(&contents)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
        Err(_) => return Err(DriverErrorKind::Unavailable),
    };
    Ok(!admitted && !native.contains_key(message))
}

impl DriverSubject for PiConformanceSubject {
    async fn describe(&mut self) -> Result<DriverDescription, DriverErrorKind> {
        let description = self.client.describe().map_err(Self::error)?;
        let protocol = description.protocol.ok_or(DriverErrorKind::Unavailable)?;
        Ok(DriverDescription {
            protocol_minimum: protocol.minimum,
            protocol_maximum: protocol.maximum,
            capabilities: description
                .capabilities
                .into_iter()
                .map(|capability| CapabilityObservation {
                    id: capability.id,
                    version: capability.version,
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
        required_capabilities: Vec<CapabilityObservation>,
    ) -> Result<ContractBinding, DriverErrorKind> {
        let offered = self.describe().await?.capabilities;
        if required_capabilities.iter().any(|required| {
            !offered.iter().any(|capability| {
                capability.id == required.id && capability.version >= required.version
            })
        }) {
            return Err(DriverErrorKind::Unsupported);
        }
        let trusted = valid_trusted_configuration("Navigator conformance fixture");
        let started = self
            .client
            .start_requiring(
                StartParameters {
                    request_id: Self::bytes(1),
                    participant_id: Self::bytes(participant),
                    launch_attempt_id: Self::bytes(launch_attempt),
                    instance_id: Self::bytes(50),
                    session_id: Self::bytes(session),
                    ownership_epoch,
                    trusted_configuration: trusted,
                },
                required_capabilities
                    .into_iter()
                    .map(|capability| v1::CapabilityRequirement {
                        id: capability.id,
                        minimum_version: capability.version,
                        parameters: Vec::new(),
                    })
                    .collect(),
            )
            .map_err(Self::error)?;
        let instance = started.instance.ok_or(DriverErrorKind::Unavailable)?;
        let binding = Self::binding(&instance);
        if let Some(state) = &self.fault_state {
            let mut state = state.lock().map_err(|_| DriverErrorKind::Unavailable)?;
            match &state.binding {
                Some(existing) if existing != &instance => return Err(DriverErrorKind::Conflict),
                Some(_) => {}
                None => state.binding = Some(instance.clone()),
            }
        }
        self.instance = Some(instance);
        Ok(binding)
    }

    async fn inspect(
        &mut self,
        instance: ContractBinding,
    ) -> Result<ContractInstance, DriverErrorKind> {
        let state = self
            .client
            .inspect(Self::protocol_instance(instance))
            .map_err(Self::error)?
            .state;
        match v1::InstanceState::try_from(state).map_err(|_| DriverErrorKind::Unavailable)? {
            v1::InstanceState::Ready => Ok(ContractInstance::Ready),
            v1::InstanceState::Idle => Ok(ContractInstance::Idle),
            v1::InstanceState::Busy => Ok(ContractInstance::Busy),
            v1::InstanceState::Disconnected => Ok(ContractInstance::Disconnected),
            v1::InstanceState::Stopped => Ok(ContractInstance::Stopped),
            v1::InstanceState::Failed => Ok(ContractInstance::Failed),
            v1::InstanceState::InstanceUncertain => Ok(ContractInstance::Uncertain),
            v1::InstanceState::Starting | v1::InstanceState::Unspecified => {
                Ok(ContractInstance::Starting)
            }
        }
    }

    async fn deliver(
        &mut self,
        instance: ContractBinding,
        message: u128,
        operation: u128,
        payload: Vec<u8>,
    ) -> Result<ContractAcceptance, DriverErrorKind> {
        let message_id = Self::derived_bytes(b"conformance.message", message);
        let operation_id = Self::derived_bytes(b"conformance.operation", operation);
        let attempt = Self::derived_bytes(b"conformance.delivery-attempt", message);
        let prompt_digest = file_digest_bytes(&payload);
        if let Some(state) = &self.fault_state {
            state
                .lock()
                .map_err(|_| DriverErrorKind::Unavailable)?
                .attempts
                .entry(message)
                .or_insert_with(|| attempt.clone());
        }
        let request = self.request();
        assert_eq!(
            [
                request.as_slice(),
                message_id.as_slice(),
                operation_id.as_slice(),
                attempt.as_slice(),
            ]
            .into_iter()
            .collect::<HashSet<_>>()
            .len(),
            4,
            "conformance wire identities must be domain-separated",
        );
        let acceptance = self
            .client
            .deliver_attempt(
                request,
                Self::protocol_instance(instance),
                message_id,
                attempt.clone(),
                operation_id,
                payload,
            )
            .map_err(|error| {
                if self.completed_fault()
                    && matches!(
                        error,
                        ClientError::Protocol | ClientError::ProtocolDetail(_)
                    )
                {
                    DriverErrorKind::Unavailable
                } else {
                    Self::error(error)
                }
            });
        let acceptance = acceptance?;
        if acceptance == v1::Acceptance::Accepted {
            let message = Self::derived_bytes(b"conformance.message", message);
            let identity = bytes_hex(&message);
            let expected = ExpectedDelivery {
                operation_id: bytes_hex(&Self::derived_bytes(b"conformance.operation", operation)),
                delivery_attempt_id: bytes_hex(&attempt),
                prompt_digest,
            };
            match self.expected_deliveries.entry(identity) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(expected);
                }
                std::collections::hash_map::Entry::Occupied(entry) if entry.get() == &expected => {}
                std::collections::hash_map::Entry::Occupied(_) => {
                    return Err(DriverErrorKind::Conflict);
                }
            }
        }
        self.attempts.entry(message).or_insert(attempt);
        map_contract_acceptance(acceptance)
    }

    async fn acceptance(
        &mut self,
        instance: ContractBinding,
        message: u128,
    ) -> Result<ContractAcceptance, DriverErrorKind> {
        let attempt = self
            .attempts
            .get(&message)
            .cloned()
            .unwrap_or_else(|| Self::derived_bytes(b"conformance.delivery-attempt", message));
        let value = self
            .client
            .query_acceptance(
                Self::protocol_instance(instance),
                Self::derived_bytes(b"conformance.message", message),
                &attempt,
            )
            .map_err(Self::error)?;
        map_contract_acceptance(value)
    }

    async fn cancel(
        &mut self,
        instance: ContractBinding,
        operation: u128,
    ) -> Result<(), DriverErrorKind> {
        let request = self.request();
        self.client
            .cancel(
                request,
                Self::protocol_instance(instance),
                Self::derived_bytes(b"conformance.operation", operation),
            )
            .map_err(Self::error)?;
        Ok(())
    }

    async fn stop(&mut self, instance: ContractBinding) -> Result<ContractStop, DriverErrorKind> {
        let request = self.request();
        match self
            .client
            .stop(request, Self::protocol_instance(instance))
            .map_err(Self::error)?
        {
            v1::StopDisposition::StoppedConfirmed => Ok(ContractStop::Confirmed),
            v1::StopDisposition::AlreadyStopped => Ok(ContractStop::AlreadyStopped),
            _ => Ok(ContractStop::Uncertain),
        }
    }

    async fn native_delivery_count(&mut self) -> Result<u64, DriverErrorKind> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let observations = self.prompt_observations()?;
            if observations.len() >= self.expected_deliveries.len() {
                if observations.len() > self.expected_deliveries.len() {
                    return Err(DriverErrorKind::Conflict);
                }
                if observations.iter().any(|digest| {
                    !self
                        .expected_deliveries
                        .values()
                        .any(|expected| &expected.prompt_digest == digest)
                }) {
                    return Err(DriverErrorKind::Conflict);
                }
                let native = match self.native_delivery_observations() {
                    Ok(native) => native,
                    Err(DriverErrorKind::Unavailable) if Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                if native.len() != self.expected_deliveries.len()
                    || self.expected_deliveries.iter().any(|(message, expected)| {
                        native.get(message)
                            != Some(&(
                                expected.delivery_attempt_id.clone(),
                                expected.prompt_digest.clone(),
                            ))
                    })
                {
                    return Err(DriverErrorKind::Conflict);
                }
                let journal = match self.journal_delivery_identities() {
                    Ok(journal) => journal,
                    Err(DriverErrorKind::Unavailable) if Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                if self.expected_deliveries.iter().any(|(message, expected)| {
                    journal.pending.get(message)
                        != Some(&(
                            expected.operation_id.clone(),
                            expected.delivery_attempt_id.clone(),
                        ))
                }) {
                    return Err(DriverErrorKind::Conflict);
                }
                let expected = self
                    .expected_deliveries
                    .keys()
                    .cloned()
                    .collect::<HashSet<_>>();
                if journal.pending.keys().cloned().collect::<HashSet<_>>() != expected {
                    return Err(DriverErrorKind::Conflict);
                }
                if !journal.delivered.is_subset(&expected) {
                    return Err(DriverErrorKind::Conflict);
                }
                if journal.delivered != expected {
                    if Instant::now() >= deadline {
                        return Err(DriverErrorKind::Unavailable);
                    }
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }
                return observations
                    .len()
                    .try_into()
                    .map_err(|_| DriverErrorKind::Unavailable);
            }
            if Instant::now() >= deadline {
                return Err(DriverErrorKind::Unavailable);
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    async fn native_cancel_count(&mut self) -> Result<u64, DriverErrorKind> {
        self.abort_count()
    }
}

fn parse_delivery_journal(contents: &str) -> Result<JournalDeliveryIdentities, DriverErrorKind> {
    if !contents.is_empty() && !contents.ends_with('\n') {
        return Err(DriverErrorKind::Unavailable);
    }
    let mut pending = HashMap::new();
    let mut delivered = HashSet::new();
    let mut binding = None;
    for (index, line) in contents.lines().filter(|line| !line.is_empty()).enumerate() {
        let record = serde_json::from_str::<serde_json::Value>(line)
            .map_err(|_| DriverErrorKind::Conflict)?;
        if record["version"] != 3 {
            return Err(DriverErrorKind::Conflict);
        }
        if index == 0 && record["kind"] != "binding" {
            return Err(DriverErrorKind::Conflict);
        }
        let record_binding = record["binding"].clone();
        if binding
            .as_ref()
            .is_some_and(|expected| expected != &record_binding)
        {
            return Err(DriverErrorKind::Conflict);
        }
        binding.get_or_insert(record_binding);
        match record["kind"].as_str() {
            Some("binding") if index == 0 => {}
            Some("pending") => {
                let message = &record["message"];
                let field = |name| {
                    message[name]
                        .as_str()
                        .map(str::to_owned)
                        .ok_or(DriverErrorKind::Conflict)
                };
                let message_id = field("messageId")?;
                let identities = (field("operationId")?, field("deliveryAttemptId")?);
                if pending.insert(message_id, identities).is_some() {
                    return Err(DriverErrorKind::Conflict);
                }
            }
            Some("delivered") => {
                let message_id = record["messageId"]
                    .as_str()
                    .ok_or(DriverErrorKind::Conflict)?;
                if !delivered.insert(message_id.to_owned()) {
                    return Err(DriverErrorKind::Conflict);
                }
            }
            Some("event" | "hierarchy_result") => {}
            Some(_) | None => return Err(DriverErrorKind::Conflict),
        }
    }
    Ok(JournalDeliveryIdentities {
        binding: binding.ok_or(DriverErrorKind::Conflict)?,
        pending,
        delivered,
    })
}

fn map_contract_acceptance(value: v1::Acceptance) -> Result<ContractAcceptance, DriverErrorKind> {
    match value {
        v1::Acceptance::Accepted => Ok(ContractAcceptance::Accepted),
        v1::Acceptance::NotAccepted => Ok(ContractAcceptance::NotAccepted),
        v1::Acceptance::Unknown => Ok(ContractAcceptance::Unknown),
        v1::Acceptance::Unspecified => Err(DriverErrorKind::Unavailable),
    }
}

impl Drop for PiHarness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn built_pi_package() -> PathBuf {
    common::pi_package::built(&workspace_root())
}

#[test]
fn fault_protocol_parses_exact_bounded_reached_frame() {
    let (mut writer, mut reader) = UnixStream::pair().unwrap();
    writer.write_all(b"{\"type\":\"REACHED\",\"point\":\"after_fsync\",\"messageId\":\"11111111111111111111111111111111\",\"deliveryAttemptId\":\"22222222222222222222222222222222\"}\n").unwrap();
    assert!(matches!(
        FaultProtocolHarness::read_fault_frame(
            &mut reader,
            Instant::now() + Duration::from_secs(1)
        )
        .unwrap(),
        PiFaultFrame::Reached {
            point: PiFaultPoint::AfterFsync,
            ..
        }
    ));
}

#[test]
fn fault_protocol_rejects_unknown_fields_uppercase_identity_and_oversize() {
    for frame in [
        b"{\"type\":\"RELEASE\",\"extra\":true}\n".to_vec(),
        b"{\"type\":\"ARM\",\"point\":\"before_append\",\"messageId\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"deliveryAttemptId\":\"22222222222222222222222222222222\"}\n".to_vec(),
        [vec![b' '; MAX_FAULT_FRAME_BYTES + 1], vec![b'\n']].concat(),
    ] {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&frame).unwrap();
        assert!(FaultProtocolHarness::read_fault_frame(&mut reader, Instant::now() + Duration::from_secs(1)).is_err());
    }
}

#[test]
fn fault_transport_requires_exact_reached_killed_and_reaped_outcome() {
    assert!(!is_completed_crash(&FaultOutcome::Armed));
    assert!(!is_completed_crash(&FaultOutcome::ReachedExact));
    assert!(!is_completed_crash(&FaultOutcome::KillSucceeded));
    assert!(!is_completed_crash(&FaultOutcome::Failed));
    assert!(!is_completed_crash(&FaultOutcome::ReapedBySignal(15)));
    assert!(is_completed_crash(&FaultOutcome::ReapedBySignal(9)));
}

fn fault_watcher_fixture() -> (
    PiFaultHarness,
    UnixStream,
    Arc<Mutex<FaultOutcome>>,
    PiFaultFrame,
    std::sync::mpsc::Receiver<()>,
) {
    let harness = PiFaultHarness::new();
    let (control, child_control) = UnixStream::pair().unwrap();
    let outcome = Arc::new(Mutex::new(FaultOutcome::Armed));
    let expected = fault_target(FaultWindow::CrashBeforeAcceptance).unwrap().1;
    let child = Command::new("/bin/sh")
        .args(["-c", "exec sleep 30"])
        .spawn()
        .unwrap();
    harness.state.lock().unwrap().process = Some(FaultProcess {
        generation: 1,
        child,
        ownership: None,
        fault_cancel: None,
        watcher: None,
        outcome: Some(Arc::clone(&outcome)),
    });
    let (completion_tx, completion_rx) = std::sync::mpsc::sync_channel(1);
    install_fault_watcher(
        &harness.state,
        child_control,
        expected.clone(),
        1,
        Arc::clone(&outcome),
        Some(completion_tx),
    )
    .unwrap();
    (harness, control, outcome, expected, completion_rx)
}

fn await_failed_fault(
    outcome: &Arc<Mutex<FaultOutcome>>,
    completion: &std::sync::mpsc::Receiver<()>,
) {
    completion
        .recv_timeout(Duration::from_secs(35))
        .expect("fault watcher exceeded its bounded read deadline");
    assert_eq!(*outcome.lock().unwrap(), FaultOutcome::Failed);
}

#[test]
fn fault_watcher_mismatch_marks_failed_and_refuses_restart() {
    let (harness, mut control, outcome, expected, completion) = fault_watcher_fixture();
    let PiFaultFrame::Reached {
        point, message_id, ..
    } = expected
    else {
        unreachable!()
    };
    let mismatch = PiFaultFrame::Reached {
        point,
        message_id,
        delivery_attempt_id: "ff".repeat(16),
    };
    serde_json::to_writer(&mut control, &mismatch).unwrap();
    control.write_all(b"\n").unwrap();
    await_failed_fault(&outcome, &completion);
    assert!(matches!(
        harness.begin_generation(),
        Err(DriverErrorKind::Conflict)
    ));
}

#[test]
fn fault_watcher_eof_marks_failed_and_refuses_restart() {
    let (harness, control, outcome, _, completion) = fault_watcher_fixture();
    drop(control);
    await_failed_fault(&outcome, &completion);
    assert!(matches!(
        harness.begin_generation(),
        Err(DriverErrorKind::Conflict)
    ));
}

#[test]
fn fault_watcher_refuses_to_detach_when_generation_is_absent() {
    let harness = PiFaultHarness::new();
    let (mut control, child_control) = UnixStream::pair().unwrap();
    let outcome = Arc::new(Mutex::new(FaultOutcome::Armed));
    let (completion_tx, completion_rx) = std::sync::mpsc::sync_channel(1);

    assert!(matches!(
        install_fault_watcher(
            &harness.state,
            child_control,
            fault_target(FaultWindow::CrashBeforeAcceptance).unwrap().1,
            1,
            Arc::clone(&outcome),
            Some(completion_tx),
        ),
        Err(DriverErrorKind::Conflict)
    ));
    assert_eq!(
        completion_rx.recv_timeout(Duration::from_millis(50)),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
    );
    assert_eq!(*outcome.lock().unwrap(), FaultOutcome::Armed);
    let mut byte = [0_u8; 1];
    assert_eq!(control.read(&mut byte).unwrap(), 0);
}

#[tokio::test]
async fn pi_process_proves_real_driver_fault_windows() {
    let mut harness = PiFaultHarness::new();
    assert_driver_fault_windows(&mut harness).await.unwrap();
}

impl PiCapabilityLaunchHarness {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let node = PathBuf::from(
            String::from_utf8(Command::new("which").arg("node").output().unwrap().stdout)
                .unwrap()
                .trim(),
        )
        .canonicalize()
        .unwrap();
        let package = built_pi_package();
        let main = package.join("dist/main.js").canonicalize().unwrap();
        let driver_id = DriverId::from_uuid(Uuid::from_u128(1)).unwrap();
        let catalog_path = directory.path().join("catalog.json");
        let catalog = serde_json::json!({"entries":{"pi":{
            "driver_id": driver_id.to_string(),
            "executable": node,
            "executable_sha256": file_digest(&node),
            "arguments": ["--preserve-symlinks", main],
            "working_directory": package,
            "environment": {},
            "protocol_version": PROTOCOL_V1,
            "ownership_channel": "dedicated_fd",
            "capabilities": [{"name":"durable.acceptance","version":1}],
            "bootstrap_configuration": {},
            "trusted_artifacts": [{"path":main,"sha256":file_digest(&main)}]
        }}});
        fs::write(&catalog_path, serde_json::to_vec(&catalog).unwrap()).unwrap();
        fs::set_permissions(&catalog_path, fs::Permissions::from_mode(0o600)).unwrap();
        let catalog = TrustedDriverCatalog::from_path(Some(&catalog_path)).unwrap();
        let resolver =
            CatalogDriverConfigResolver::new(catalog, None, directory.path().join("control"));
        let spawn_calls = Arc::new(AtomicU64::new(0));
        let backend = UnixProcessBackend::new_with_spawn_counter(
            directory.path().join("credentials"),
            Some(Arc::clone(&spawn_calls)),
        )
        .unwrap();
        Self {
            _directory: directory,
            resolver,
            driver_id,
            backend,
            spawn_calls,
        }
    }

    fn template(&self, capability: CapabilityObservation) -> navigator_store_api::TemplateRecord {
        let requirement = DriverCapabilityRequirement::new(
            Capability::new(capability.id).unwrap(),
            capability.version,
            [],
        )
        .unwrap();
        Template::register(
            TemplateId::from_uuid(Uuid::from_u128(2)).unwrap(),
            BoundedText::new("Pi capability conformance".to_owned()).unwrap(),
            DriverRequirement::new(self.driver_id, vec![requirement]).unwrap(),
            TrustedConfiguration::new(BoundedText::new("trusted".to_owned()).unwrap(), []).unwrap(),
            ResourceBounds::new(1024, 1_000, 1).unwrap(),
            InputSchema::new(Vec::new()).unwrap(),
        )
        .unwrap()
        .registration_snapshot()
    }
}

impl CapabilityLaunchHarness for PiCapabilityLaunchHarness {
    fn native_process_count(&self) -> u64 {
        self.spawn_calls.load(Ordering::Acquire)
    }

    async fn start_requiring(
        &mut self,
        capability: CapabilityObservation,
    ) -> Result<(), DriverErrorKind> {
        let template = self.template(capability);
        let config = self
            .resolver
            .resolve(&template)
            .map_err(|_| DriverErrorKind::Unsupported)?;
        let id = |value| Uuid::from_u128(value);
        let plan = LaunchPlan {
            session_id: SessionId::from_uuid(id(10)).unwrap(),
            participant_id: ParticipantId::from_uuid(id(11)).unwrap(),
            driver_id: config.driver_id,
            driver_configuration_digest: [1; 32],
            attempt_id: LaunchAttemptId::from_uuid(id(12)).unwrap(),
            instance_id: InstanceId::from_uuid(id(13)).unwrap(),
            host_id: HostId::from_uuid(id(14)).unwrap(),
            ownership_epoch: FencingEpoch::new(1).unwrap(),
            prepare_request_id: RequestId::from_uuid(id(15)).unwrap(),
            attach_request_id: RequestId::from_uuid(id(16)).unwrap(),
            compensation_request_id: RequestId::from_uuid(id(17)).unwrap(),
            compensation_terminal_request_id: RequestId::from_uuid(id(18)).unwrap(),
            program: config.program,
            expected_executable_identity: config.expected_executable_identity,
            arguments: config.arguments,
            working_directory: config.working_directory,
            environment: config.environment,
            environment_allowlist: config.environment_allowlist,
            ownership_channel: config.ownership_channel,
            process_io_mode: config.process_io_mode,
            bootstrap_configuration: config.bootstrap_configuration,
        };
        let evidence = self
            .backend
            .spawn(&plan, SECRET)
            .await
            .map_err(|_| DriverErrorKind::Unavailable)?;
        let _ = self
            .backend
            .force_stop_group(plan.attempt_id, &evidence)
            .await;
        Ok(())
    }
}

fn file_digest(path: &Path) -> String {
    file_digest_bytes(&fs::read(path).unwrap())
}

fn file_digest_bytes(bytes: &[u8]) -> String {
    bytes_hex(&Sha256::digest(bytes))
}

fn bytes_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 0x0f)]),
            ]
        })
        .collect()
}

fn runtime_bootstrap(directory: &Path, provider: &Path) -> PathBuf {
    let path = directory.join("bootstrap.json");
    fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({
            "provider": "faux", "model": "faux-1",
            "authPath": directory.join("auth.json"), "providerModule": provider,
            "abortObserverPath": "native-aborts.log",
            "promptObserverPath": "native-prompts.log",
            "deliveryObserverPath": "native-deliveries.log",
            "cwd": directory, "tools": [],
        }))
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn session_file(directory: &Path) -> PathBuf {
    directory.join(format!(
        "{}-{}-{}.jsonl",
        "03".repeat(16),
        "04".repeat(16),
        "05".repeat(16)
    ))
}

fn faux_provider_module() -> String {
    let module = workspace_root()
        .join("packages/navigator-driver-pi/node_modules/@earendil-works/pi-ai/dist/index.js");
    format!(
        "import {{ fauxAssistantMessage, fauxProvider, fauxToolCall }} from {:?};\n\
         export function register(runtime) {{\n\
           const faux = fauxProvider({{ tokensPerSecond: 1000 }});\n\
           faux.setResponses([\n\
             fauxAssistantMessage(fauxToolCall('navigator_report', {{kind:'succeeded',payload:'done'}}), {{stopReason:'toolUse'}}),\n\
             fauxAssistantMessage('settled')\n\
           ]);\n\
           runtime.registerNativeProvider(faux.provider);\n\
         }}\n",
        format!("file://{}", module.display())
    )
}

fn blocked_faux_provider_module(entered: &Path, _release: &Path) -> String {
    let module = workspace_root()
        .join("packages/navigator-driver-pi/node_modules/@earendil-works/pi-ai/dist/index.js");
    format!(
        "import {{ writeFileSync }} from 'node:fs';\n\
         import {{ fauxAssistantMessage, fauxProvider }} from {:?};\n\
         export function register(runtime) {{\n\
           const faux = fauxProvider({{ tokensPerSecond: 1000 }});\n\
           faux.setResponses([async () => {{\n\
             writeFileSync({:?}, 'entered');\n\
             await new Promise(() => {{}});\n\
             return fauxAssistantMessage('released');\n\
           }}]);\n\
           runtime.registerNativeProvider(faux.provider);\n\
         }}\n",
        format!("file://{}", module.display()),
        entered.display().to_string(),
    )
}

fn report_then_blocked_provider_module(entered: &Path, _release: &Path) -> String {
    let module = workspace_root()
        .join("packages/navigator-driver-pi/node_modules/@earendil-works/pi-ai/dist/index.js");
    format!(
        "import {{ writeFileSync }} from 'node:fs';\n\
         import {{ fauxAssistantMessage, fauxProvider, fauxToolCall }} from {:?};\n\
         export function register(runtime) {{\n\
           const faux = fauxProvider({{ tokensPerSecond: 1000 }});\n\
           faux.setResponses([\n\
             fauxAssistantMessage(fauxToolCall('navigator_report', {{kind:'succeeded',payload:'done'}}), {{stopReason:'toolUse'}}),\n\
             async () => {{ writeFileSync({:?}, 'entered'); await new Promise(() => {{}}); return fauxAssistantMessage('released'); }}\n\
           ]);\n\
           runtime.registerNativeProvider(faux.provider);\n\
         }}\n",
        format!("file://{}", module.display()),
        entered.display().to_string(),
    )
}

fn hierarchy_waiter_provider_module() -> String {
    let module = workspace_root()
        .join("packages/navigator-driver-pi/node_modules/@earendil-works/pi-ai/dist/index.js");
    format!(
        "import {{ fauxAssistantMessage, fauxProvider, fauxToolCall }} from {:?};\n\
         export function register(runtime) {{ const faux=fauxProvider({{tokensPerSecond:1000}});\n\
         faux.setResponses([fauxAssistantMessage(fauxToolCall('navigator_spawn_child',\
         {{request_id:'28'.repeat(16),template_id:'29'.repeat(16),task_input_base64:'e30='}}),{{stopReason:'toolUse'}})]);\n\
         runtime.registerNativeProvider(faux.provider); }}\n",
        format!("file://{}", module.display())
    )
}

fn create_fifo(path: &Path) {
    assert!(Command::new("mkfifo").arg(path).status().unwrap().success());
}

fn spawn_pi_in(directory: &Path, provider_source: &str) -> (Child, PathBuf, PathBuf) {
    let credential = directory.join("credential");
    let socket = directory.join("control.sock");
    let session = session_file(directory);
    let provider = directory.join("provider.mjs");
    fs::write(&credential, SECRET).unwrap();
    fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&provider, provider_source).unwrap();
    let bootstrap = runtime_bootstrap(directory, &provider);
    let child = Command::new("/bin/sh")
        .args([
            "-c",
            "exec 3<&0; exec 0</dev/null; exec node --preserve-symlinks dist/main.js",
        ])
        .current_dir(built_pi_package())
        .env("NAVIGATOR_CONTROL_SOCKET", &socket)
        .env("NAVIGATOR_CREDENTIAL_FILE", credential)
        .env("NAVIGATOR_DRIVER_ID", "01010101010101010101010101010101")
        .env("NAVIGATOR_DRIVER_BOOTSTRAP_FILE", bootstrap)
        .env("NAVIGATOR_DRIVER_PRIVATE_ROOT", directory)
        .env("NAVIGATOR_OWNERSHIP_FD", "3")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    while fs::symlink_metadata(&socket).is_err() {
        assert!(Instant::now() < deadline, "Pi Driver did not create UDS");
        thread::yield_now();
    }
    while UnixStream::connect(&socket).is_err() {
        assert!(Instant::now() < deadline, "Pi Driver UDS was not accepting");
        thread::yield_now();
    }
    (child, socket, session)
}

fn spawn_pi_with_dedicated_ownership(
    directory: &Path,
    provider_source: &str,
) -> (Child, UnixStream, PathBuf, PathBuf) {
    let credential = directory.join("credential");
    let socket = directory.join("control.sock");
    let session = session_file(directory);
    let provider = directory.join("provider.mjs");
    fs::write(&credential, SECRET).unwrap();
    fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&provider, provider_source).unwrap();
    let bootstrap = runtime_bootstrap(directory, &provider);
    let (owner, child_channel) = UnixStream::pair().unwrap();
    let mut command = Command::new("node");
    command
        .args(["--preserve-symlinks", "dist/main.js"])
        .current_dir(built_pi_package())
        .env("NAVIGATOR_CONTROL_SOCKET", &socket)
        .env("NAVIGATOR_CREDENTIAL_FILE", credential)
        .env("NAVIGATOR_DRIVER_ID", "01010101010101010101010101010101")
        .env("NAVIGATOR_DRIVER_BOOTSTRAP_FILE", bootstrap)
        .env("NAVIGATOR_DRIVER_PRIVATE_ROOT", directory)
        .env("NAVIGATOR_OWNERSHIP_FD", "3")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    command
        .fd_mappings(vec![FdMapping {
            parent_fd: child_channel.into(),
            child_fd: 3,
        }])
        .unwrap();
    let child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    while UnixStream::connect(&socket).is_err() {
        assert!(Instant::now() < deadline, "Pi Driver UDS was not accepting");
        thread::yield_now();
    }
    (child, owner, socket, session)
}

fn connect(socket: &Path) -> DriverClient {
    DriverClient::connect(
        socket,
        DriverCredential::new(SECRET.to_vec()).unwrap(),
        Duration::from_secs(3),
    )
    .unwrap()
}

fn trusted_configuration(_directory: &Path, _session: &Path) -> Vec<u8> {
    valid_trusted_configuration("Navigator crash fixture")
}

fn valid_trusted_configuration(base_instructions: &str) -> Vec<u8> {
    common::valid_trusted_configuration(base_instructions)
}

fn wire_frame(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
    let mut frame = Vec::new();
    let mut size = 0_usize;
    for shift in (0..35).step_by(7) {
        let mut byte = [0_u8];
        stream.read_exact(&mut byte)?;
        frame.push(byte[0]);
        size |= usize::from(byte[0] & 0x7f) << shift;
        if byte[0] & 0x80 == 0 {
            break;
        }
    }
    let offset = frame.len();
    frame.resize(offset + size, 0);
    stream.read_exact(&mut frame[offset..])?;
    Ok(frame)
}

fn discard_one_authenticated_response(
    directory: &Path,
    server: &Path,
) -> (PathBuf, mpsc::Receiver<()>, thread::JoinHandle<()>) {
    let proxy = directory.join("discard-response.sock");
    let listener = UnixListener::bind(&proxy).unwrap();
    fs::set_permissions(&proxy, fs::Permissions::from_mode(0o600)).unwrap();
    let server = server.to_path_buf();
    let (sent, received) = mpsc::sync_channel(0);
    let worker = thread::spawn(move || {
        let (mut client, _) = listener.accept().unwrap();
        let mut upstream = UnixStream::connect(server).unwrap();
        upstream
            .write_all(&wire_frame(&mut client).unwrap())
            .unwrap();
        let _authenticated_response = wire_frame(&mut upstream).unwrap();
        sent.send(()).unwrap();
    });
    (proxy, received, worker)
}

fn recover_pending_delivery(directory: &Path, session: &Path, expected: &v1::InstanceIdentity) {
    let normal_provider = faux_provider_module();
    let (mut restarted, socket, _) = spawn_pi_in(directory, &normal_provider);
    let mut recovered = connect(&socket);
    let instance = recovered
        .start(
            id(12),
            id(3),
            id(4),
            id(5),
            id(6),
            7,
            trusted_configuration(directory, session),
        )
        .unwrap()
        .instance
        .unwrap();
    assert_eq!(&instance, expected);
    assert_eq!(
        recovered
            .deliver_attempt(
                id(13),
                instance.clone(),
                id(8),
                id(9),
                id(10),
                b"work".to_vec(),
            )
            .unwrap(),
        v1::Acceptance::Accepted
    );
    assert_eq!(
        recovered
            .query_acceptance(instance.clone(), id(8), &id(9))
            .unwrap(),
        v1::Acceptance::Accepted
    );
    assert!(matches!(
        recovered.observe(instance.clone(), 1).unwrap().event,
        Some(v1::driver_event::Event::Acceptance(_))
    ));
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok(event) = connect(&socket).observe(instance.clone(), 2) {
            assert!(matches!(
                event.event,
                Some(v1::driver_event::Event::Report(_))
            ));
            break;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        matches!(
            recovered.observe(expected.clone(), 3),
            Ok(navigator_driver_client::Observation::NoEvent)
        ),
        "recovery emitted a duplicate outbound Event"
    );
    restarted.kill().unwrap();
    restarted.wait().unwrap();
}

fn id(byte: u8) -> Vec<u8> {
    vec![byte; 16]
}

fn signed_describe() -> v1::Envelope {
    let request_id = id(42);
    let mut envelope = v1::Envelope {
        envelope_id: id(41),
        response_authenticator: Vec::new(),
        response_to_request_id: Vec::new(),
        body: Some(v1::envelope::Body::DescribeRequest(v1::DescribeRequest {
            metadata: Some(v1::RequestMetadata {
                protocol_version: PROTOCOL_V1,
                authentication: Some(v1::Authentication {
                    key_id: Sha256::digest(SECRET)[..16].to_vec(),
                    nonce: id(43),
                    expires_unix_ms: i64::try_from(
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis(),
                    )
                    .unwrap()
                        + 30_000,
                    authenticator: Vec::new(),
                    request_digest: Vec::new(),
                }),
                required_capabilities: Vec::new(),
                request_id: request_id.clone(),
            }),
        })),
    };
    let digest = canonical_request_digest(&envelope).unwrap();
    let metadata = match envelope.body.as_mut().unwrap() {
        v1::envelope::Body::DescribeRequest(request) => request.metadata.as_mut().unwrap(),
        _ => unreachable!(),
    };
    metadata.authentication.as_mut().unwrap().request_digest = digest.to_vec();
    metadata.authentication.as_mut().unwrap().authenticator = authentication_tag(
        SECRET,
        &id(41),
        &request_id,
        PROTOCOL_V1,
        metadata.authentication.as_ref().unwrap(),
        &[],
        &[],
    )
    .unwrap()
    .to_vec();
    envelope
}

fn raw_call(socket: &Path, envelope: &v1::Envelope) -> std::io::Result<Vec<u8>> {
    let body = envelope.encode_to_vec();
    let mut stream = UnixStream::connect(socket)?;
    let mut remaining = body.len();
    loop {
        let mut byte = u8::try_from(remaining & 0x7f).unwrap();
        remaining >>= 7;
        if remaining != 0 {
            byte |= 0x80;
        }
        stream.write_all(&[byte])?;
        if remaining == 0 {
            break;
        }
    }
    stream.write_all(&body)?;
    let mut length = 0_usize;
    for shift in (0..35).step_by(7) {
        let mut byte = [0_u8];
        stream.read_exact(&mut byte)?;
        length |= usize::from(byte[0] & 0x7f) << shift;
        if byte[0] & 0x80 == 0 {
            break;
        }
    }
    let mut response = vec![0; length];
    stream.read_exact(&mut response)?;
    Ok(response)
}

fn verify_exact_replay(harness: &PiHarness, instance: &v1::InstanceIdentity) {
    let mut client = harness.client(SECRET).unwrap();
    assert_eq!(
        client
            .deliver_attempt(
                id(14),
                instance.clone(),
                id(8),
                id(9),
                id(10),
                b"work".to_vec(),
            )
            .unwrap(),
        v1::Acceptance::Accepted
    );
    assert_eq!(
        client
            .query_acceptance(instance.clone(), id(8), &id(9))
            .unwrap(),
        v1::Acceptance::Accepted
    );
    assert!(
        matches!(
            client.observe(instance.clone(), 3),
            Ok(navigator_driver_client::Observation::NoEvent)
        ),
        "exact replay emitted a duplicate report"
    );
}

fn verify_reconnect_and_stop(
    harness: &PiHarness,
    instance: v1::InstanceIdentity,
    mut client: DriverClient,
) {
    let mut wrong_identity = instance.clone();
    wrong_identity.launch_attempt_id = id(99);
    assert!(client.inspect(wrong_identity).is_err());
    drop(client);
    verify_exact_replay(harness, &instance);
    let mut reconnected = harness.client(SECRET).unwrap();
    assert_eq!(
        reconnected.stop(id(13), instance).unwrap(),
        v1::StopDisposition::StoppedConfirmed
    );
}

fn completed_delivery(client: &mut DriverClient) -> v1::InstanceIdentity {
    let trusted = valid_trusted_configuration("Navigator empty-poll fixture");
    let instance = client
        .start(id(20), id(21), id(22), id(23), id(24), 7, trusted)
        .unwrap()
        .instance
        .unwrap();
    assert!(matches!(
        client.observe(instance.clone(), 0).unwrap().event,
        Some(v1::driver_event::Event::Ready(_))
    ));
    assert_eq!(
        client
            .deliver_attempt(
                id(25),
                instance.clone(),
                id(26),
                id(27),
                id(28),
                b"work".to_vec(),
            )
            .unwrap(),
        v1::Acceptance::Accepted
    );
    assert!(matches!(
        client.observe(instance.clone(), 1).unwrap().event,
        Some(v1::driver_event::Event::Acceptance(_))
    ));
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if client
            .observe(instance.clone(), 2)
            .is_ok_and(|event| matches!(event.event, Some(v1::driver_event::Event::Report(_))))
        {
            return instance;
        }
        assert!(
            Instant::now() < deadline,
            "Pi did not emit the fixture report"
        );
    }
}

#[test]
fn empty_observe_poll_releases_one_authenticated_channel_for_controls_without_spinning() {
    let harness = PiHarness::spawn();
    let mut client = harness.client(SECRET).unwrap();
    let instance = completed_delivery(&mut client);
    let client = Arc::new(Mutex::new(client));
    let polling = Arc::new(AtomicBool::new(true));
    let in_observe = Arc::new(AtomicBool::new(false));
    let polls = Arc::new(AtomicUsize::new(0));
    let worker = {
        let client = Arc::clone(&client);
        let instance = instance.clone();
        let polling = Arc::clone(&polling);
        let in_observe = Arc::clone(&in_observe);
        let polls = Arc::clone(&polls);
        thread::spawn(move || {
            while polling.load(Ordering::Acquire) {
                let mut locked = client.lock().unwrap();
                in_observe.store(true, Ordering::Release);
                let observation = locked.observe(instance.clone(), 3);
                in_observe.store(false, Ordering::Release);
                drop(locked);
                assert!(matches!(
                    observation,
                    Ok(navigator_driver_client::Observation::NoEvent)
                ));
                polls.fetch_add(1, Ordering::AcqRel);
                thread::sleep(Duration::from_millis(1));
            }
        })
    };

    let control = |call: &mut dyn FnMut(&mut DriverClient)| {
        let deadline = Instant::now() + Duration::from_secs(1);
        while !in_observe.load(Ordering::Acquire) {
            assert!(
                Instant::now() < deadline,
                "empty poll did not enter Observe"
            );
            thread::yield_now();
        }
        let started = Instant::now();
        call(&mut client.lock().unwrap());
        assert!(started.elapsed() < Duration::from_millis(500));
    };
    control(&mut |client| {
        assert_eq!(
            client
                .reminder(instance.clone(), id(29), id(28), id(26))
                .unwrap()
                .disposition,
            v1::RemindDisposition::ReminderRequested as i32
        );
    });
    control(&mut |client| {
        assert_eq!(
            client.cancel(id(30), instance.clone(), id(28)).unwrap(),
            v1::CancelDisposition::CancelRequested
        );
    });
    control(&mut |client| {
        polling.store(false, Ordering::Release);
        assert_eq!(
            client.stop(id(31), instance.clone()).unwrap(),
            v1::StopDisposition::StoppedConfirmed
        );
    });
    worker.join().unwrap();
    assert!((3..=12).contains(&polls.load(Ordering::Acquire)));
}

#[tokio::test]
async fn pi_process_passes_the_normative_driver_contract_oracles() {
    let mut lifecycle = PiConformanceSubject::spawn();
    assert_driver_contract(&mut lifecycle).await.unwrap();

    let mut acceptance = PiConformanceSubject::spawn();
    assert_durable_acceptance_contract(&mut acceptance)
        .await
        .unwrap();
}

#[test]
fn delivery_journal_oracle_preserves_field_positions_and_rejects_duplicates() {
    let binding = serde_json::json!({"driverId":"driver"});
    let header = serde_json::json!({"version":3,"kind":"binding","binding":binding});
    let pending = serde_json::json!({
        "version": 3,
        "kind": "pending",
        "binding": binding,
        "message": {
            "messageId": "message",
            "operationId": "operation",
            "deliveryAttemptId": "attempt"
        }
    });
    let delivered =
        serde_json::json!({"version":3,"kind":"delivered","binding":binding,"messageId":"message"});
    let journal = parse_delivery_journal(&format!("{header}\n{pending}\n{delivered}\n")).unwrap();
    assert_eq!(
        journal.pending.get("message"),
        Some(&("operation".to_owned(), "attempt".to_owned()))
    );
    assert_eq!(journal.delivered, HashSet::from(["message".to_owned()]));
    assert_eq!(
        parse_delivery_journal(&format!("{header}\n{pending}\n{pending}\n")).err(),
        Some(DriverErrorKind::Conflict)
    );
    assert_eq!(
        parse_delivery_journal(&format!("{header}\n{delivered}\n{delivered}\n")).err(),
        Some(DriverErrorKind::Conflict)
    );
    for invalid in [
        serde_json::json!({"version":2,"kind":"binding","binding":binding}).to_string(),
        serde_json::json!({"version":3,"kind":"unknown","binding":binding}).to_string(),
        pending.to_string(),
    ] {
        assert_eq!(
            parse_delivery_journal(&format!("{invalid}\n")).err(),
            Some(DriverErrorKind::Conflict)
        );
    }
}

#[test]
fn native_delivery_oracle_binds_message_attempt_and_prompt_once() {
    let record = r#"{"messageId":"11111111111111111111111111111111","deliveryAttemptId":"22222222222222222222222222222222","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    let parsed = parse_native_delivery_observations(&format!("{record}\n")).unwrap();
    assert_eq!(
        parsed.get("11111111111111111111111111111111"),
        Some(&(
            "22222222222222222222222222222222".to_owned(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()
        ))
    );
    assert_eq!(
        parse_native_delivery_observations(&format!("{record}\n{record}\n")).err(),
        Some(DriverErrorKind::Conflict)
    );
    assert_eq!(
        parse_native_delivery_observations("{\"messageId\":\"unexpected\"}\n").err(),
        Some(DriverErrorKind::Conflict)
    );
}

#[test]
fn ownership_oracle_rejects_post_eof_native_admission() {
    let directory = tempfile::tempdir().unwrap();
    let message = "11".repeat(16);
    let attempt = "22".repeat(16);
    fs::write(
        directory.path().join("native-deliveries.log"),
        format!(
            "{{\"messageId\":\"{message}\",\"deliveryAttemptId\":\"{attempt}\",\"sha256\":\"{}\"}}\n",
            "33".repeat(32)
        ),
    )
    .unwrap();
    assert!(!ownership_identity_absent(directory.path(), &message).unwrap());
}

#[test]
fn bootstrap_child_guard_reaps_process_before_harness_construction() {
    let child = Command::new("/bin/sh")
        .args(["-c", "exec sleep 30"])
        .spawn()
        .unwrap();
    let pid = child.id().to_string();
    drop(ChildGuard::new(child));
    assert!(
        !Command::new("kill")
            .args(["-0", &pid])
            .status()
            .unwrap()
            .success()
    );
}

#[tokio::test]
async fn pi_catalog_rejects_missing_capability_before_process_launch() {
    let mut capability = PiCapabilityLaunchHarness::new();
    assert_missing_capability_prevents_launch(&mut capability)
        .await
        .unwrap();
}

#[test]
fn pi_executable_uses_the_authenticated_generated_protocol_end_to_end() {
    let harness = PiHarness::spawn();
    assert_eq!(
        fs::symlink_metadata(&harness.socket)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let mut client = harness.client(SECRET).unwrap();
    let description = client.describe().unwrap();
    assert_eq!(description.driver_id, id(1));
    assert_eq!(description.protocol.unwrap().minimum, 1);

    let trusted = valid_trusted_configuration("Navigator black-box fixture");
    let started = client
        .start(id(2), id(3), id(4), id(5), id(6), 7, trusted)
        .unwrap();
    let instance = started.instance.unwrap();
    assert_eq!(instance.launch_attempt_id, id(4));
    assert_eq!(instance.ownership_epoch, 7);
    assert_eq!(
        v1::InstanceState::try_from(client.inspect(instance.clone()).unwrap().state).unwrap(),
        v1::InstanceState::Ready
    );
    assert!(matches!(
        client.observe(instance.clone(), 0).unwrap().event,
        Some(v1::driver_event::Event::Ready(_))
    ));

    assert_eq!(
        client
            .deliver_attempt(
                id(7),
                instance.clone(),
                id(8),
                id(9),
                id(10),
                b"work".to_vec()
            )
            .unwrap(),
        v1::Acceptance::Accepted
    );
    assert_eq!(
        client
            .query_acceptance(instance.clone(), id(8), &id(9))
            .unwrap(),
        v1::Acceptance::Accepted
    );
    let acceptance = client.observe(instance.clone(), 1).unwrap();
    assert!(matches!(
        acceptance.event,
        Some(v1::driver_event::Event::Acceptance(_))
    ));
    let deadline = Instant::now() + Duration::from_secs(3);
    let report = loop {
        if let Ok(event) = harness.client(SECRET).unwrap().observe(instance.clone(), 2) {
            break event;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    };
    assert!(
        matches!(report.event, Some(v1::driver_event::Event::Report(_))),
        "expected report event, got {:?}",
        report.event
    );
    assert_eq!(report.in_reply_to, acceptance.in_reply_to);
    assert!(
        harness
            .client(SECRET)
            .unwrap()
            .reminder(instance.clone(), id(110), id(99), id(98))
            .is_err(),
        "wrong Operation/Message reminder reached Pi"
    );
    assert!(
        harness
            .client(SECRET)
            .unwrap()
            .cancel(id(111), instance.clone(), id(99))
            .is_err(),
        "wrong Operation cancellation reached Pi"
    );
    assert_eq!(
        client
            .reminder(instance.clone(), id(11), id(10), id(8))
            .unwrap()
            .disposition,
        v1::RemindDisposition::ReminderRequested as i32
    );
    assert_eq!(
        client.cancel(id(12), instance.clone(), id(10)).unwrap(),
        v1::CancelDisposition::CancelRequested
    );

    verify_reconnect_and_stop(&harness, instance, client);
}

#[test]
fn pi_executable_rejects_forged_authentication_without_starting_an_instance() {
    let harness = PiHarness::spawn();
    let mut forged = harness
        .client(b"wrong-secret-wrong-secret-12345678")
        .unwrap();
    assert!(forged.describe().is_err(), "forged client was accepted");
    assert!(!harness.session_file.exists());
    assert_eq!(
        harness
            .client(SECRET)
            .unwrap()
            .describe()
            .unwrap()
            .driver_id,
        id(1),
        "forged authentication poisoned the listener for the valid owner"
    );
}

#[test]
fn pi_executable_isolates_an_oversized_frame_and_keeps_accepting_authenticated_clients() {
    let harness = PiHarness::spawn();
    let mut raw = UnixStream::connect(&harness.socket).unwrap();
    // Canonical varint for MAX_FRAME_BYTES + 1; the body is deliberately absent.
    raw.write_all(&[0x81, 0x80, 0x40]).unwrap();
    drop(raw);
    let mut owner = harness.client(SECRET).unwrap();
    assert_eq!(owner.describe().unwrap().driver_id, id(1));
}

#[test]
fn pi_executable_isolates_disconnect_before_request_dispatch() {
    let harness = PiHarness::spawn();
    drop(UnixStream::connect(&harness.socket).unwrap());
    let mut owner = harness.client(SECRET).unwrap();
    assert_eq!(owner.describe().unwrap().driver_id, id(1));
}

#[test]
fn pi_executable_rejects_an_authenticated_nonce_replay() {
    let harness = PiHarness::spawn();
    let request = signed_describe();
    assert!(!raw_call(&harness.socket, &request).unwrap().is_empty());
    assert!(raw_call(&harness.socket, &request).is_err());
    let mut fresh = harness.client(SECRET).unwrap();
    assert_eq!(fresh.describe().unwrap().driver_id, id(1));
}

#[test]
fn pi_executable_relinquishes_ownership_on_stdin_eof_within_the_bound() {
    let mut harness = PiHarness::spawn();
    drop(harness.child.stdin.take());
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if harness.child.try_wait().unwrap().is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Pi Driver retained ownership after supervisor EOF"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(!harness.socket.exists());
}

#[test]
fn crash_after_inbox_commit_reopens_lock_and_redelivers_the_exact_identity_once() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let entered = directory.path().join("entered.fifo");
    let release = directory.path().join("release.fifo");
    create_fifo(&entered);
    create_fifo(&release);
    let blocked_provider = blocked_faux_provider_module(&entered, &release);
    let (mut crashed, socket, session) = spawn_pi_in(directory.path(), &blocked_provider);
    let trusted = trusted_configuration(directory.path(), &session);
    let mut owner = connect(&socket);
    let instance = owner
        .start(id(2), id(3), id(4), id(5), id(6), 7, trusted.clone())
        .unwrap()
        .instance
        .unwrap();
    let delivery_instance = instance.clone();
    let delivery = thread::spawn(move || {
        owner.deliver_attempt(
            id(7),
            delivery_instance,
            id(8),
            id(9),
            id(10),
            b"work".to_vec(),
        )
    });
    let mut signal = fs::File::open(&entered).unwrap();
    let mut marker = [0_u8; 7];
    signal.read_exact(&mut marker).unwrap();
    assert_eq!(&marker, b"entered");
    crashed.kill().unwrap();
    crashed.wait().unwrap();
    assert_eq!(delivery.join().unwrap().unwrap(), v1::Acceptance::Accepted);
    if socket.exists() {
        fs::remove_file(&socket).unwrap();
    }

    recover_pending_delivery(directory.path(), &session, &instance);
}

#[test]
fn crash_after_report_before_delivery_response_replays_one_observable_report() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let entered = directory.path().join("report-entered.fifo");
    let release = directory.path().join("report-release.fifo");
    create_fifo(&entered);
    create_fifo(&release);
    let provider = report_then_blocked_provider_module(&entered, &release);
    let (mut crashed, socket, session) = spawn_pi_in(directory.path(), &provider);
    let mut owner = connect(&socket);
    let instance = owner
        .start(
            id(2),
            id(3),
            id(4),
            id(5),
            id(6),
            7,
            trusted_configuration(directory.path(), &session),
        )
        .unwrap()
        .instance
        .unwrap();
    let delivery_instance = instance.clone();
    let delivery = thread::spawn(move || {
        owner.deliver_attempt(
            id(7),
            delivery_instance,
            id(8),
            id(9),
            id(10),
            b"work".to_vec(),
        )
    });
    let mut signal = fs::File::open(&entered).unwrap();
    let mut marker = [0_u8; 7];
    signal.read_exact(&mut marker).unwrap();
    assert_eq!(&marker, b"entered");
    crashed.kill().unwrap();
    crashed.wait().unwrap();
    assert_eq!(delivery.join().unwrap().unwrap(), v1::Acceptance::Accepted);
    if socket.exists() {
        fs::remove_file(socket).unwrap();
    }
    recover_pending_delivery(directory.path(), &session, &instance);
}

#[test]
fn disconnect_after_acceptance_response_commit_recovers_exact_durable_acceptance() {
    let harness = PiHarness::spawn();
    let mut owner = harness.client(SECRET).unwrap();
    let instance = owner
        .start(
            id(2),
            id(3),
            id(4),
            id(5),
            id(6),
            7,
            trusted_configuration(harness.directory.path(), &harness.session_file),
        )
        .unwrap()
        .instance
        .unwrap();
    let (proxy, response_committed, proxy_worker) =
        discard_one_authenticated_response(harness.directory.path(), &harness.socket);
    let delivery_instance = instance.clone();
    let delivery = thread::spawn(move || {
        let mut client = connect(&proxy);
        client.deliver_attempt(
            id(7),
            delivery_instance,
            id(8),
            id(9),
            id(10),
            b"work".to_vec(),
        )
    });
    response_committed.recv().unwrap();
    proxy_worker.join().unwrap();
    assert!(delivery.join().unwrap().is_err());

    assert_eq!(
        owner
            .query_acceptance(instance.clone(), id(8), &id(9))
            .unwrap(),
        v1::Acceptance::Accepted
    );
    assert!(matches!(
        owner.observe(instance.clone(), 1).unwrap().event,
        Some(v1::driver_event::Event::Acceptance(_))
    ));
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok(event) = harness.client(SECRET).unwrap().observe(instance.clone(), 2) {
            assert!(matches!(
                event.event,
                Some(v1::driver_event::Event::Report(_))
            ));
            break;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn ownership_eof_interrupts_delivery_blocked_inside_the_provider() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let entered = directory.path().join("shutdown-entered.fifo");
    let release = directory.path().join("shutdown-release.fifo");
    create_fifo(&entered);
    create_fifo(&release);
    let provider = blocked_faux_provider_module(&entered, &release);
    let (mut child, mut ownership, socket, session) =
        spawn_pi_with_dedicated_ownership(directory.path(), &provider);
    let mut owner = connect(&socket);
    let instance = owner
        .start(
            id(2),
            id(3),
            id(4),
            id(5),
            id(6),
            7,
            trusted_configuration(directory.path(), &session),
        )
        .unwrap()
        .instance
        .unwrap();
    let delivery = thread::spawn(move || {
        owner.deliver_attempt(id(7), instance, id(8), id(9), id(10), b"work".to_vec())
    });
    let mut signal = fs::File::open(&entered).unwrap();
    let mut marker = [0_u8; 7];
    signal.read_exact(&mut marker).unwrap();
    assert_eq!(&marker, b"entered");
    ownership.write_all(&[1]).unwrap();
    ownership.flush().unwrap();
    drop(ownership);
    let deadline = Instant::now() + Duration::from_secs(3);
    let exited = loop {
        if child.try_wait().unwrap().is_some() {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        thread::yield_now();
    };
    if !exited {
        child.kill().unwrap();
        child.wait().unwrap();
    }
    assert_eq!(delivery.join().unwrap().unwrap(), v1::Acceptance::Accepted);
    assert!(exited, "ownership EOF did not cancel provider");
    assert!(!socket.exists());
}

fn verify_uncertain_hierarchy_reopen(
    directory: &Path,
    provider: &str,
    session: &Path,
    instance: v1::InstanceIdentity,
    command_event: &navigator_driver_client::Observation,
) {
    let (mut restarted, restarted_socket, _) = spawn_pi_in(directory, provider);
    let mut recovered = connect(&restarted_socket);
    let reopened = recovered
        .start(
            id(12),
            id(3),
            id(4),
            id(5),
            id(6),
            7,
            trusted_configuration(directory, session),
        )
        .unwrap()
        .instance
        .unwrap();
    assert_eq!(reopened, instance);
    assert_eq!(
        v1::InstanceState::try_from(recovered.inspect(instance.clone()).unwrap().state).unwrap(),
        v1::InstanceState::InstanceUncertain
    );
    let replayed = recovered.observe(instance.clone(), 2).unwrap();
    assert_eq!(replayed.event_id, command_event.event_id);
    assert_eq!(replayed.sequence, command_event.sequence);
    assert_eq!(replayed.event, command_event.event);
    assert!(
        recovered
            .deliver_attempt(
                id(13),
                instance.clone(),
                id(14),
                id(15),
                id(16),
                b"blocked".to_vec()
            )
            .is_err()
    );
    let result = v1::hierarchy_result_request::Result::Spawned(v1::SpawnChildResult {
        participant_id: id(40),
        operation_id: id(41),
        input_message_id: id(42),
    });
    connect(&restarted_socket)
        .hierarchy_result(id(20), instance.clone(), id(40), result.clone())
        .unwrap();
    connect(&restarted_socket)
        .hierarchy_result(id(21), instance.clone(), id(40), result)
        .unwrap();
    let changed = v1::hierarchy_result_request::Result::Spawned(v1::SpawnChildResult {
        participant_id: id(43),
        operation_id: id(41),
        input_message_id: id(42),
    });
    assert!(
        connect(&restarted_socket)
            .hierarchy_result(id(22), instance, id(40), changed)
            .is_err()
    );
    restarted.kill().unwrap();
    restarted.wait().unwrap();
}

#[test]
fn crash_after_durable_hierarchy_command_reopens_uncertain_without_duplicate() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let provider = hierarchy_waiter_provider_module();
    let (mut crashed, socket, session) = spawn_pi_in(directory.path(), &provider);
    let mut owner = connect(&socket);
    let instance = owner
        .start(
            id(2),
            id(3),
            id(4),
            id(5),
            id(6),
            7,
            trusted_configuration(directory.path(), &session),
        )
        .unwrap()
        .instance
        .unwrap();
    let delivery_instance = instance.clone();
    let delivery = thread::spawn(move || {
        owner.deliver_attempt(
            id(7),
            delivery_instance,
            id(8),
            id(9),
            id(10),
            b"spawn".to_vec(),
        )
    });
    let mut observer = connect(&socket);
    assert!(matches!(
        observer.observe(instance.clone(), 0).unwrap().event,
        Some(v1::driver_event::Event::Ready(_))
    ));
    let deadline = Instant::now() + Duration::from_secs(3);
    let command_event = loop {
        if let Ok(event) = connect(&socket).observe(instance.clone(), 2) {
            break event;
        }
        assert!(
            Instant::now() < deadline,
            "hierarchy command was not emitted"
        );
        thread::sleep(Duration::from_millis(10));
    };
    let Some(v1::driver_event::Event::HierarchyCommand(command)) = &command_event.event else {
        panic!("missing hierarchy command")
    };
    let acceptance = connect(&socket).observe(instance.clone(), 1).unwrap();
    assert_eq!(command_event.in_reply_to, acceptance.in_reply_to);
    assert_eq!(command.request_id, id(40));
    crashed.kill().unwrap();
    crashed.wait().unwrap();
    assert_eq!(delivery.join().unwrap().unwrap(), v1::Acceptance::Accepted);
    if socket.exists() {
        fs::remove_file(&socket).unwrap();
    }
    verify_uncertain_hierarchy_reopen(
        directory.path(),
        &provider,
        &session,
        instance,
        &command_event,
    );
}
