use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::net::UnixStream,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use command_fds::{CommandFdExt, FdMapping};
use navigator_domain::LaunchAttemptId;
use navigator_store_api::ProcessEvidence;
use nix::{
    errno::Errno,
    fcntl::{FcntlArg, OFlag, fcntl},
    pty::openpty,
    sys::signal::{Signal, kill, killpg},
    unistd::{Pid, getpgid},
};
use sha2::{Digest, Sha256};
use tokio::{
    process::{Child, ChildStdin},
    sync::Mutex,
    time::sleep,
};

use crate::{
    CredentialSource, IdentityObservation, LaunchPlan, OwnershipChannel, ProcessBackend,
    ProcessIoMode, SupervisorError,
};

#[derive(Default)]
pub struct OsCredentialSource;

impl CredentialSource for OsCredentialSource {
    fn next_credential(&mut self) -> Result<Vec<u8>, SupervisorError> {
        let mut credential = vec![0_u8; 32];
        fs::File::open("/dev/urandom")
            .and_then(|mut source| source.read_exact(&mut credential))
            .map_err(|_| SupervisorError::Process)?;
        Ok(credential)
    }
}

enum OwnershipWriter {
    Stdin(ChildStdin),
    Dedicated(UnixStream),
}

struct OwnedProcess {
    child: Child,
    evidence: ProcessEvidence,
    credential_path: PathBuf,
    bootstrap_path: PathBuf,
    private_root: PathBuf,
    private_root_device: u64,
    private_root_inode: u64,
    private_root_owner: u32,
    ownership_channel: Option<OwnershipWriter>,
    executable_path: PathBuf,
    terminal_master: Option<fs::File>,
}

struct PendingSpawn {
    command: tokio::process::Command,
    attempt_id: LaunchAttemptId,
    ownership_mode: OwnershipChannel,
    executable_path: PathBuf,
    executable_identity: [u8; 32],
    creation_marker: u64,
    credential_path: PathBuf,
    bootstrap_path: PathBuf,
    private_root: PathBuf,
    private_root_device: u64,
    private_root_inode: u64,
    private_root_owner: u32,
    terminal_master: Option<fs::File>,
    dedicated_parent: Option<UnixStream>,
}

/// Owns non-adoptable child handles; restart recovery must use `reconcile_launch`.
pub struct UnixProcessBackend {
    credential_directory: PathBuf,
    processes: Arc<Mutex<HashMap<LaunchAttemptId, OwnedProcess>>>,
    creation_marker: AtomicU64,
    spawn_counter: Option<Arc<AtomicU64>>,
}

impl UnixProcessBackend {
    pub const MAX_TERMINAL_FRAME_BYTES: usize = 65_536;

    pub fn new(credential_directory: PathBuf) -> Result<Self, SupervisorError> {
        Self::new_with_spawn_counter(credential_directory, None)
    }

    /// Returns the attempt-private control socket owned by this backend.
    #[must_use]
    pub fn managed_control_socket_path(&self, attempt_id: LaunchAttemptId) -> PathBuf {
        self.private_root_path(attempt_id).join("c")
    }

    fn private_root_path(&self, attempt_id: LaunchAttemptId) -> PathBuf {
        self.credential_directory
            .parent()
            .expect("canonical credential directory has a parent")
            .join(format!(".{:032x}", attempt_id.as_uuid().as_u128()))
    }

    fn private_root_marker(attempt_id: LaunchAttemptId) -> Vec<u8> {
        format!("navigator-owned-private-root-v1\n{attempt_id}\n").into_bytes()
    }

    pub fn new_with_spawn_counter(
        credential_directory: PathBuf,
        spawn_counter: Option<Arc<AtomicU64>>,
    ) -> Result<Self, SupervisorError> {
        if !credential_directory.is_absolute() {
            return Err(SupervisorError::Process);
        }
        create_private_directory(&credential_directory)?;
        let credential_directory =
            fs::canonicalize(credential_directory).map_err(|_| SupervisorError::Process)?;
        Ok(Self {
            credential_directory,
            processes: Arc::new(Mutex::new(HashMap::new())),
            creation_marker: AtomicU64::new(1),
            spawn_counter,
        })
    }

    fn verify_owned(
        process: &mut OwnedProcess,
        expected: &ProcessEvidence,
    ) -> Result<bool, SupervisorError> {
        if &process.evidence != expected
            || expected.process_id == 0
            || expected.process_group_id != expected.process_id
            || expected.creation_marker == 0
            || expected.parent_process_id != std::process::id()
            || process.child.id() != Some(expected.process_id)
            || digest_file(&process.executable_path).ok().as_ref()
                != Some(&expected.executable_identity)
        {
            return Ok(false);
        }
        if process
            .child
            .try_wait()
            .map_err(|_| SupervisorError::Process)?
            .is_some()
        {
            return Ok(false);
        }
        let pid = i32::try_from(expected.process_id).map_err(|_| SupervisorError::Process)?;
        let group =
            i32::try_from(expected.process_group_id).map_err(|_| SupervisorError::Process)?;
        Ok(getpgid(Some(Pid::from_raw(pid))).ok() == Some(Pid::from_raw(group)))
    }

    pub async fn write_terminal(
        &self,
        attempt_id: LaunchAttemptId,
        expected: &ProcessEvidence,
        bytes: &[u8],
        deadline: tokio::time::Instant,
    ) -> Result<(), SupervisorError> {
        if bytes.is_empty() || bytes.len() > Self::MAX_TERMINAL_FRAME_BYTES {
            return Err(SupervisorError::Process);
        }
        let mut written = 0;
        while written < bytes.len() {
            if tokio::time::Instant::now() >= deadline {
                return Err(SupervisorError::Timeout);
            }
            let result = {
                let mut processes = self.processes.lock().await;
                let process = processes
                    .get_mut(&attempt_id)
                    .ok_or(SupervisorError::IdentityMismatch)?;
                if !Self::verify_owned(process, expected)? {
                    return Err(SupervisorError::IdentityMismatch);
                }
                process
                    .terminal_master
                    .as_mut()
                    .ok_or(SupervisorError::Process)?
                    .write(&bytes[written..])
            };
            match result {
                Ok(0) => return Err(SupervisorError::Process),
                Ok(count) => written += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    sleep(Duration::from_millis(1)).await;
                }
                Err(_) => return Err(SupervisorError::Process),
            }
        }
        Ok(())
    }

    pub async fn read_terminal(
        &self,
        attempt_id: LaunchAttemptId,
        expected: &ProcessEvidence,
        limit: usize,
        deadline: tokio::time::Instant,
    ) -> Result<Vec<u8>, SupervisorError> {
        if limit == 0 || limit > Self::MAX_TERMINAL_FRAME_BYTES {
            return Err(SupervisorError::Process);
        }
        let mut output = vec![0; limit];
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(SupervisorError::Timeout);
            }
            let result = {
                let mut processes = self.processes.lock().await;
                let process = processes
                    .get_mut(&attempt_id)
                    .ok_or(SupervisorError::IdentityMismatch)?;
                if &process.evidence != expected {
                    return Err(SupervisorError::IdentityMismatch);
                }
                process
                    .terminal_master
                    .as_mut()
                    .ok_or(SupervisorError::Process)?
                    .read(&mut output)
            };
            match result {
                Ok(0) => return Err(SupervisorError::Process),
                Ok(count) => {
                    output.truncate(count);
                    return Ok(output);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    sleep(Duration::from_millis(1)).await;
                }
                Err(_) => return Err(SupervisorError::Process),
            }
        }
    }

    async fn observation(
        &self,
        attempt_id: LaunchAttemptId,
        expected: &ProcessEvidence,
    ) -> Result<IdentityObservation, SupervisorError> {
        let mut processes = self.processes.lock().await;
        let Some(process) = processes.get_mut(&attempt_id) else {
            return Ok(IdentityObservation::Mismatch);
        };
        if !Self::verify_owned(process, expected)? {
            if process
                .child
                .try_wait()
                .map_err(|_| SupervisorError::Process)?
                .is_some()
                && &process.evidence == expected
            {
                return Ok(IdentityObservation::Exited);
            }
            return Ok(IdentityObservation::Mismatch);
        }
        Ok(IdentityObservation::Same)
    }

    async fn signal(
        &self,
        attempt_id: LaunchAttemptId,
        expected: &ProcessEvidence,
        signal: Signal,
    ) -> Result<(), SupervisorError> {
        let mut processes = self.processes.lock().await;
        let Some(process) = processes.get_mut(&attempt_id) else {
            return Err(SupervisorError::IdentityMismatch);
        };
        // Group signalling is permitted only while Navigator retains the original Child handle.
        if !Self::verify_owned(process, expected)? {
            return Err(SupervisorError::IdentityMismatch);
        }
        let group =
            i32::try_from(expected.process_group_id).map_err(|_| SupervisorError::Process)?;
        if getpgid(Some(Pid::from_raw(group))).ok() != Some(Pid::from_raw(group)) {
            return Err(SupervisorError::IdentityMismatch);
        }
        killpg(Pid::from_raw(group), signal).map_err(|_| SupervisorError::Process)
    }
}

fn configure_process_io(
    plan: &LaunchPlan,
    command: &mut tokio::process::Command,
) -> Result<(Option<fs::File>, Option<UnixStream>), SupervisorError> {
    let terminal_master = match plan.process_io_mode {
        ProcessIoMode::Headless => None,
        ProcessIoMode::TerminalPty => {
            if plan.ownership_channel != OwnershipChannel::DedicatedFd {
                return Err(SupervisorError::Process);
            }
            let pty = openpty(None, None).map_err(|_| SupervisorError::Process)?;
            let master = fs::File::from(pty.master);
            fcntl(&master, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))
                .map_err(|_| SupervisorError::Process)?;
            let slave = fs::File::from(pty.slave);
            command
                .stdin(std::process::Stdio::from(
                    slave.try_clone().map_err(|_| SupervisorError::Process)?,
                ))
                .stdout(std::process::Stdio::from(
                    slave.try_clone().map_err(|_| SupervisorError::Process)?,
                ))
                .stderr(std::process::Stdio::from(slave));
            Some(master)
        }
    };
    let dedicated_parent = match plan.ownership_channel {
        OwnershipChannel::Stdin => {
            command.stdin(std::process::Stdio::piped());
            None
        }
        OwnershipChannel::DedicatedFd => {
            let (parent, child) = UnixStream::pair().map_err(|_| SupervisorError::Process)?;
            command
                .as_std_mut()
                .fd_mappings(vec![FdMapping {
                    parent_fd: child.into(),
                    child_fd: 3,
                }])
                .map_err(|_| SupervisorError::Process)?;
            command.env("NAVIGATOR_OWNERSHIP_FD", "3");
            if plan.process_io_mode == ProcessIoMode::Headless {
                command.stdin(std::process::Stdio::null());
            }
            Some(parent)
        }
    };
    Ok((terminal_master, dedicated_parent))
}

async fn rollback_spawned_process(
    child: &mut Child,
    attempt_id: LaunchAttemptId,
    credential_path: &Path,
    bootstrap_path: &Path,
    private_root: &Path,
    private_root_identity: (u64, u64, u32),
) {
    let group = child
        .id()
        .and_then(|process_id| i32::try_from(process_id).ok());
    if let Some(group) = group {
        let _ = killpg(Pid::from_raw(group), Signal::SIGKILL);
    }
    let leader_reaped = tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .is_ok();
    let group_absent =
        group.is_none_or(|group| matches!(kill(Pid::from_raw(-group), None), Err(Errno::ESRCH)));
    if leader_reaped && group_absent {
        let _ = fs::remove_file(credential_path);
        let _ = fs::remove_file(bootstrap_path);
        let _ = remove_owned_private_root(private_root, attempt_id, Some(private_root_identity));
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "spawn ownership setup and rollback must retain one exact process/root identity boundary"
)]
async fn complete_spawn(
    pending: PendingSpawn,
    processes: Arc<Mutex<HashMap<LaunchAttemptId, OwnedProcess>>>,
) -> Result<ProcessEvidence, SupervisorError> {
    let PendingSpawn {
        mut command,
        attempt_id,
        ownership_mode,
        executable_path,
        executable_identity,
        creation_marker,
        credential_path,
        bootstrap_path,
        private_root,
        private_root_device,
        private_root_inode,
        private_root_owner,
        terminal_master,
        dedicated_parent,
    } = pending;
    let spawned = tokio::task::spawn_blocking(move || command.spawn()).await;
    let Ok(Ok(mut child)) = spawned else {
        let _ = fs::remove_file(&credential_path);
        let _ = fs::remove_file(&bootstrap_path);
        let _ = fs::remove_dir_all(&private_root);
        return Err(SupervisorError::Process);
    };
    let ownership_channel = match ownership_mode {
        OwnershipChannel::Stdin => {
            let Some(writer) = child.stdin.take() else {
                rollback_spawned_process(
                    &mut child,
                    attempt_id,
                    &credential_path,
                    &bootstrap_path,
                    &private_root,
                    (private_root_device, private_root_inode, private_root_owner),
                )
                .await;
                return Err(SupervisorError::Process);
            };
            OwnershipWriter::Stdin(writer)
        }
        OwnershipChannel::DedicatedFd => {
            let Some(writer) = dedicated_parent else {
                rollback_spawned_process(
                    &mut child,
                    attempt_id,
                    &credential_path,
                    &bootstrap_path,
                    &private_root,
                    (private_root_device, private_root_inode, private_root_owner),
                )
                .await;
                return Err(SupervisorError::Process);
            };
            OwnershipWriter::Dedicated(writer)
        }
    };
    let Some(process_id) = child.id() else {
        rollback_spawned_process(
            &mut child,
            attempt_id,
            &credential_path,
            &bootstrap_path,
            &private_root,
            (private_root_device, private_root_inode, private_root_owner),
        )
        .await;
        return Err(SupervisorError::Process);
    };
    if digest_file(&executable_path).ok().as_ref() != Some(&executable_identity) {
        rollback_spawned_process(
            &mut child,
            attempt_id,
            &credential_path,
            &bootstrap_path,
            &private_root,
            (private_root_device, private_root_inode, private_root_owner),
        )
        .await;
        return Err(SupervisorError::IdentityMismatch);
    }
    let evidence = ProcessEvidence {
        process_id,
        process_group_id: process_id,
        parent_process_id: std::process::id(),
        creation_marker,
        executable_identity,
    };
    processes.lock().await.insert(
        attempt_id,
        OwnedProcess {
            child,
            evidence: evidence.clone(),
            credential_path,
            bootstrap_path,
            private_root,
            private_root_device,
            private_root_inode,
            private_root_owner,
            ownership_channel: Some(ownership_channel),
            executable_path,
            terminal_master,
        },
    );
    Ok(evidence)
}

impl ProcessBackend for UnixProcessBackend {
    async fn spawn(
        &self,
        plan: &LaunchPlan,
        credential: &[u8],
    ) -> Result<ProcessEvidence, SupervisorError> {
        if digest_file(&plan.program).ok() != Some(plan.expected_executable_identity) {
            return Err(SupervisorError::IdentityMismatch);
        }
        let credential_path = self
            .credential_directory
            .join(format!("{}.credential", plan.attempt_id));
        write_private_file(&credential_path, credential)?;
        let bootstrap_path = self
            .credential_directory
            .join(format!("{}.bootstrap.json", plan.attempt_id));
        let private_root = self.private_root_path(plan.attempt_id);
        fs::create_dir(&private_root).map_err(|_| SupervisorError::Process)?;
        fs::set_permissions(&private_root, fs::Permissions::from_mode(0o700))
            .map_err(|_| SupervisorError::Process)?;
        write_private_file(
            &private_root.join(".navigator-owner"),
            &Self::private_root_marker(plan.attempt_id),
        )?;
        let private_root_metadata =
            fs::symlink_metadata(&private_root).map_err(|_| SupervisorError::Process)?;
        write_private_file(&bootstrap_path, &plan.bootstrap_configuration)?;

        let executable_identity = plan.expected_executable_identity;
        let mut command = tokio::process::Command::new(&plan.program);
        command
            .args(&plan.arguments)
            .current_dir(&plan.working_directory)
            .env_clear()
            .envs(&plan.environment)
            .env("NAVIGATOR_CREDENTIAL_FILE", &credential_path)
            .env("NAVIGATOR_DRIVER_BOOTSTRAP_FILE", &bootstrap_path)
            .env("NAVIGATOR_DRIVER_PRIVATE_ROOT", &private_root)
            .env(
                "NAVIGATOR_DRIVER_ID",
                plan.driver_id.as_uuid().simple().to_string(),
            )
            .kill_on_drop(true);
        let (terminal_master, dedicated_parent) = configure_process_io(plan, &mut command)?;
        command.as_std_mut().process_group(0);
        let attempt_id = plan.attempt_id;
        let ownership_mode = plan.ownership_channel;
        let executable_path = plan.program.clone();
        let creation_marker = self.creation_marker.fetch_add(1, Ordering::Relaxed);
        let processes = Arc::clone(&self.processes);
        let owner = tokio::spawn(complete_spawn(
            PendingSpawn {
                command,
                attempt_id,
                ownership_mode,
                executable_path,
                executable_identity,
                creation_marker,
                credential_path,
                bootstrap_path,
                private_root,
                private_root_device: private_root_metadata.dev(),
                private_root_inode: private_root_metadata.ino(),
                private_root_owner: private_root_metadata.uid(),
                terminal_master,
                dedicated_parent,
            },
            processes,
        ));
        let evidence = owner.await.map_err(|_| SupervisorError::Process)??;
        if let Some(counter) = &self.spawn_counter {
            counter.fetch_add(1, Ordering::AcqRel);
        }
        Ok(evidence)
    }

    async fn inspect(
        &self,
        attempt_id: LaunchAttemptId,
        expected: &ProcessEvidence,
    ) -> Result<IdentityObservation, SupervisorError> {
        self.observation(attempt_id, expected).await
    }

    async fn graceful_stop(
        &self,
        attempt_id: LaunchAttemptId,
        expected: &ProcessEvidence,
    ) -> Result<(), SupervisorError> {
        self.signal(attempt_id, expected, Signal::SIGTERM).await
    }

    async fn force_stop_group(
        &self,
        attempt_id: LaunchAttemptId,
        expected: &ProcessEvidence,
    ) -> Result<(), SupervisorError> {
        self.signal(attempt_id, expected, Signal::SIGKILL).await
    }

    async fn wait_for_exit(
        &self,
        attempt_id: LaunchAttemptId,
        timeout: Duration,
    ) -> Result<bool, SupervisorError> {
        let deadline = Instant::now() + timeout;
        loop {
            let mut processes = self.processes.lock().await;
            let Some(process) = processes.get_mut(&attempt_id) else {
                return Ok(false);
            };
            let leader_exited = process
                .child
                .try_wait()
                .map_err(|_| SupervisorError::Process)?
                .is_some();
            if leader_exited {
                let group = i32::try_from(process.evidence.process_group_id)
                    .map_err(|_| SupervisorError::Process)?;
                if let Err(Errno::ESRCH) = kill(Pid::from_raw(-group), None) {
                    return Ok(true);
                }
            }
            drop(processes);
            if Instant::now() >= deadline {
                return Ok(false);
            }
            sleep(Duration::from_millis(10).min(timeout)).await;
        }
    }

    async fn revoke_ownership(&self, attempt_id: LaunchAttemptId) -> Result<(), SupervisorError> {
        let mut processes = self.processes.lock().await;
        let process = processes
            .get_mut(&attempt_id)
            .ok_or(SupervisorError::NotAttached)?;
        if let Some(channel) = process.ownership_channel.take() {
            match channel {
                OwnershipWriter::Stdin(writer) => drop(writer),
                OwnershipWriter::Dedicated(mut writer) => {
                    writer
                        .write_all(&[0])
                        .map_err(|_| SupervisorError::Process)?;
                    drop(writer);
                }
            }
        }
        drop(process.terminal_master.take());
        remove_file_if_exists(&process.credential_path)
    }

    async fn cleanup(&self, attempt_id: LaunchAttemptId) -> Result<(), SupervisorError> {
        let mut processes = self.processes.lock().await;
        if let Some(process) = processes.get_mut(&attempt_id) {
            let leader_exited = process
                .child
                .try_wait()
                .map_err(|_| SupervisorError::Process)?
                .is_some();
            let group = i32::try_from(process.evidence.process_group_id)
                .map_err(|_| SupervisorError::Process)?;
            let group_exited = matches!(kill(Pid::from_raw(-group), None), Err(Errno::ESRCH));
            if !leader_exited || !group_exited {
                return Err(SupervisorError::Process);
            }
        }
        let process = processes.get(&attempt_id);
        let private_root = self.private_root_path(attempt_id);
        let expected_root = process.as_ref().map(|tracked| {
            if tracked.private_root != private_root {
                return Err(SupervisorError::Process);
            }
            Ok((
                tracked.private_root_device,
                tracked.private_root_inode,
                tracked.private_root_owner,
            ))
        });
        let expected_root = expected_root.transpose()?;
        remove_owned_private_root(&private_root, attempt_id, expected_root)?;
        let credential_path = process.as_ref().map_or_else(
            || {
                self.credential_directory
                    .join(format!("{attempt_id}.credential"))
            },
            |tracked| tracked.credential_path.clone(),
        );
        let bootstrap_path = process.as_ref().map_or_else(
            || {
                self.credential_directory
                    .join(format!("{attempt_id}.bootstrap.json"))
            },
            |tracked| tracked.bootstrap_path.clone(),
        );
        remove_file_if_exists(&credential_path)?;
        remove_file_if_exists(&bootstrap_path)?;
        processes.remove(&attempt_id);
        drop(processes);
        Ok(())
    }
}

fn create_private_directory(path: &Path) -> Result<(), SupervisorError> {
    let parent = path.parent().ok_or(SupervisorError::Process)?;
    let owner = validate_private_directory(parent, None)?;
    match fs::symlink_metadata(path) {
        Ok(_) => validate_private_directory(path, Some(owner)).map(|_| ()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|_| SupervisorError::Process)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| SupervisorError::Process)?;
            validate_private_directory(path, Some(owner)).map(|_| ())
        }
        Err(_) => Err(SupervisorError::Process),
    }
}

fn validate_private_directory(
    path: &Path,
    expected_owner: Option<u32>,
) -> Result<u32, SupervisorError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| SupervisorError::Process)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || expected_owner.is_some_and(|owner| metadata.uid() != owner)
        || metadata.mode() & 0o077 != 0
    {
        return Err(SupervisorError::Process);
    }
    Ok(metadata.uid())
}

fn digest_file(path: &Path) -> Result<[u8; 32], SupervisorError> {
    const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
    let mut file = fs::File::open(path).map_err(|_| SupervisorError::Process)?;
    if file.metadata().map_err(|_| SupervisorError::Process)?.len() > MAX_EXECUTABLE_BYTES {
        return Err(SupervisorError::Process);
    }
    let mut digest = Sha256::new();
    std::io::copy(&mut file, &mut digest).map_err(|_| SupervisorError::Process)?;
    Ok(digest.finalize().into())
}

fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), SupervisorError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| SupervisorError::Process)?;
    file.write_all(contents)
        .map_err(|_| SupervisorError::Process)?;
    file.sync_all().map_err(|_| SupervisorError::Process)
}

fn remove_file_if_exists(path: &Path) -> Result<(), SupervisorError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(SupervisorError::Process),
    }
}

fn remove_owned_private_root(
    private_root: &Path,
    attempt_id: LaunchAttemptId,
    expected_identity: Option<(u64, u64, u32)>,
) -> Result<(), SupervisorError> {
    match fs::symlink_metadata(private_root) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir()
                || metadata.file_type().is_symlink()
                || metadata.mode() & 0o077 != 0
                || expected_identity.is_some_and(|(device, inode, owner)| {
                    metadata.dev() != device || metadata.ino() != inode || metadata.uid() != owner
                })
                || fs::read(private_root.join(".navigator-owner")).ok()
                    != Some(UnixProcessBackend::private_root_marker(attempt_id))
            {
                return Err(SupervisorError::Process);
            }
            fs::remove_dir_all(private_root).map_err(|_| SupervisorError::Process)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(SupervisorError::Process),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap, ffi::OsString, os::unix::fs::PermissionsExt, path::PathBuf,
        sync::Arc, time::Duration,
    };

    use navigator_domain::{
        DriverId, FencingEpoch, HostId, InstanceId, LaunchAttemptId, ParticipantId, RequestId,
        SessionId,
    };
    use tempfile::TempDir;
    use uuid::Uuid;

    use super::{
        IdentityObservation, LaunchPlan, OwnershipChannel, ProcessBackend, ProcessIoMode,
        UnixProcessBackend,
    };

    fn id<T>(
        value: u128,
        build: impl FnOnce(Uuid) -> Result<T, navigator_domain::InvalidIdentity>,
    ) -> T {
        build(Uuid::from_u128(value)).unwrap()
    }

    fn plan(directory: &TempDir) -> LaunchPlan {
        LaunchPlan {
            session_id: id(1, SessionId::from_uuid),
            participant_id: id(2, ParticipantId::from_uuid),
            driver_id: id(3, DriverId::from_uuid),
            driver_configuration_digest: [15; 32],
            attempt_id: id(4, LaunchAttemptId::from_uuid),
            instance_id: id(5, InstanceId::from_uuid),
            host_id: id(6, HostId::from_uuid),
            ownership_epoch: FencingEpoch::new(1).unwrap(),
            prepare_request_id: id(7, RequestId::from_uuid),
            attach_request_id: id(8, RequestId::from_uuid),
            compensation_request_id: id(9, RequestId::from_uuid),
            compensation_terminal_request_id: id(10, RequestId::from_uuid),
            program: "/bin/sh".into(),
            expected_executable_identity: super::digest_file(std::path::Path::new("/bin/sh"))
                .unwrap(),
            arguments: vec![
                "-c".into(),
                "test -z \"$HOME\" && test \"$ALLOWED\" = yes; sleep 30".into(),
            ],
            working_directory: directory.path().into(),
            environment: BTreeMap::from([(OsString::from("ALLOWED"), OsString::from("yes"))]),
            environment_allowlist: [OsString::from("ALLOWED")].into_iter().collect(),
            ownership_channel: OwnershipChannel::Stdin,
            process_io_mode: ProcessIoMode::Headless,
            bootstrap_configuration: Vec::new(),
        }
    }

    fn credential_directory(directory: &TempDir) -> PathBuf {
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        directory.path().join("credentials")
    }

    #[test]
    fn credential_directory_rejects_symlink_without_touching_target() {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new().unwrap();
        let parent = credential_directory(&directory);
        let target = directory.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&target, &parent).unwrap();

        assert!(UnixProcessBackend::new(parent).is_err());
        assert_eq!(
            std::fs::metadata(target).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn credential_directory_rejects_relative_paths() {
        assert!(UnixProcessBackend::new(PathBuf::from("relative-credentials")).is_err());
    }

    #[tokio::test]
    async fn managed_control_root_is_removed_only_when_its_identity_matches() {
        let directory = TempDir::new().unwrap();
        let backend = Arc::new(UnixProcessBackend::new(credential_directory(&directory)).unwrap());
        let plan = plan(&directory);
        let root = backend.private_root_path(plan.attempt_id);
        let socket = backend.managed_control_socket_path(plan.attempt_id);
        let evidence = backend.spawn(&plan, &[31; 32]).await.unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();

        let renamed = directory.path().join("renamed-owned-root");
        std::fs::rename(&root, &renamed).unwrap();
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Make every ownership proof except the captured filesystem identity
        // valid, so this oracle specifically kills a cleanup implementation
        // that stops checking device/inode/owner.
        std::fs::copy(
            renamed.join(".navigator-owner"),
            root.join(".navigator-owner"),
        )
        .unwrap();
        std::fs::write(root.join("replacement-sentinel"), b"preserve").unwrap();
        backend
            .force_stop_group(plan.attempt_id, &evidence)
            .await
            .unwrap();
        assert!(
            backend
                .wait_for_exit(plan.attempt_id, Duration::from_secs(2))
                .await
                .unwrap()
        );
        assert!(backend.cleanup(plan.attempt_id).await.is_err());
        assert_eq!(
            std::fs::read(root.join("replacement-sentinel")).unwrap(),
            b"preserve"
        );
        assert!(renamed.exists());
        drop(listener);
    }

    #[tokio::test]
    async fn managed_control_socket_is_removed_with_the_owned_process_root() {
        let directory = TempDir::new().unwrap();
        let backend = Arc::new(UnixProcessBackend::new(credential_directory(&directory)).unwrap());
        let plan = plan(&directory);
        let root = backend.private_root_path(plan.attempt_id);
        let socket = backend.managed_control_socket_path(plan.attempt_id);
        let evidence = backend.spawn(&plan, &[32; 32]).await.unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        backend
            .force_stop_group(plan.attempt_id, &evidence)
            .await
            .unwrap();
        assert!(
            backend
                .wait_for_exit(plan.attempt_id, Duration::from_secs(2))
                .await
                .unwrap()
        );
        backend.cleanup(plan.attempt_id).await.unwrap();
        assert!(!root.exists());
        drop(listener);
    }

    #[tokio::test]
    async fn restarted_backend_removes_only_a_marked_residual_attempt_root() {
        let directory = TempDir::new().unwrap();
        let credential_directory = credential_directory(&directory);
        let backend_a = UnixProcessBackend::new(credential_directory.clone()).unwrap();
        let plan = plan(&directory);
        let attempt = plan.attempt_id;
        let root = backend_a.private_root_path(attempt);
        let socket = backend_a.managed_control_socket_path(attempt);
        let evidence = backend_a.spawn(&plan, &[44; 32]).await.unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        backend_a
            .force_stop_group(attempt, &evidence)
            .await
            .unwrap();
        assert!(
            backend_a
                .wait_for_exit(attempt, Duration::from_secs(2))
                .await
                .unwrap()
        );
        drop(backend_a);

        // A fresh backend has no in-memory OwnedProcess. It must recognize and
        // remove the exact residual root emitted by the production spawn path.
        let backend_b = UnixProcessBackend::new(credential_directory).unwrap();
        backend_b.cleanup(attempt).await.unwrap();
        assert!(!root.exists());
        drop(listener);

        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(
            root.join(".navigator-owner"),
            UnixProcessBackend::private_root_marker(id(45, LaunchAttemptId::from_uuid)),
        )
        .unwrap();
        std::fs::write(root.join("wrong-attempt"), b"preserve").unwrap();
        assert!(backend_b.cleanup(attempt).await.is_err());
        assert_eq!(
            std::fs::read(root.join("wrong-attempt")).unwrap(),
            b"preserve"
        );

        std::fs::remove_dir_all(&root).unwrap();
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(root.join("unowned"), b"preserve").unwrap();
        assert!(backend_b.cleanup(attempt).await.is_err());
        assert_eq!(std::fs::read(root.join("unowned")).unwrap(), b"preserve");
    }

    #[tokio::test]
    async fn mismatched_evidence_never_signals_owned_or_unrelated_process() {
        let directory = TempDir::new().unwrap();
        let backend = Arc::new(UnixProcessBackend::new(credential_directory(&directory)).unwrap());
        let plan = plan(&directory);
        let evidence = backend.spawn(&plan, &[3; 32]).await.unwrap();
        for mutate in [0_u8, 1, 2, 3] {
            let mut forged = evidence.clone();
            match mutate {
                0 => forged.creation_marker += 1,
                1 => forged.parent_process_id += 1,
                2 => forged.executable_identity[0] ^= 1,
                _ => forged.process_group_id += 1,
            }
            assert_eq!(
                backend.inspect(plan.attempt_id, &forged).await.unwrap(),
                IdentityObservation::Mismatch
            );
            assert!(
                backend
                    .force_stop_group(plan.attempt_id, &forged)
                    .await
                    .is_err()
            );
        }
        assert_eq!(
            backend.inspect(plan.attempt_id, &evidence).await.unwrap(),
            IdentityObservation::Same
        );

        backend
            .force_stop_group(plan.attempt_id, &evidence)
            .await
            .unwrap();
        assert!(
            backend
                .wait_for_exit(plan.attempt_id, Duration::from_secs(2))
                .await
                .unwrap()
        );
        backend.cleanup(plan.attempt_id).await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_spawn_caller_cannot_abandon_a_live_unowned_process() {
        let directory = TempDir::new().unwrap();
        let backend = Arc::new(UnixProcessBackend::new(credential_directory(&directory)).unwrap());
        let mut plan = plan(&directory);
        let marker = directory.path().join("spawned");
        plan.arguments = vec!["-c".into(), "touch \"$MARKER\"; sleep 30".into()];
        plan.environment
            .insert("MARKER".into(), marker.as_os_str().to_owned());
        plan.environment_allowlist.insert("MARKER".into());
        let attempt_id = plan.attempt_id;
        let registry = backend.processes.lock().await;
        let subject = Arc::clone(&backend);
        let caller = tokio::spawn(async move { subject.spawn(&plan, &[19; 32]).await });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !marker.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        caller.abort();
        let _ = caller.await;
        drop(registry);
        let evidence = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(process) = backend.processes.lock().await.get(&attempt_id) {
                    break process.evidence.clone();
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            backend.inspect(attempt_id, &evidence).await.unwrap(),
            IdentityObservation::Same
        );
        assert!(backend.cleanup(attempt_id).await.is_err());
        assert_eq!(
            backend.inspect(attempt_id, &evidence).await.unwrap(),
            IdentityObservation::Same
        );
        backend
            .force_stop_group(attempt_id, &evidence)
            .await
            .unwrap();
        assert!(
            backend
                .wait_for_exit(attempt_id, Duration::from_secs(2))
                .await
                .unwrap()
        );
        backend.cleanup(attempt_id).await.unwrap();
    }

    #[test]
    fn launch_plan_debug_redacts_arguments_and_environment() {
        let directory = TempDir::new().unwrap();
        let mut plan = plan(&directory);
        let sentinel = "unique-private-launch-sentinel";
        plan.arguments.push(sentinel.into());
        plan.environment
            .insert("PRIVATE_VALUE".into(), sentinel.into());
        let debug = format!("{plan:?}");
        assert!(!debug.contains(sentinel));
        assert!(!debug.contains("PRIVATE_VALUE"));
    }

    #[tokio::test]
    async fn ownership_channel_eof_causes_conforming_child_to_exit_without_signal() {
        let directory = TempDir::new().unwrap();
        let backend = UnixProcessBackend::new(credential_directory(&directory)).unwrap();
        let mut plan = plan(&directory);
        plan.arguments = vec!["-c".into(), "read ownership".into()];
        let evidence = backend.spawn(&plan, &[4; 32]).await.unwrap();
        assert_eq!(
            backend.inspect(plan.attempt_id, &evidence).await.unwrap(),
            IdentityObservation::Same
        );
        backend.revoke_ownership(plan.attempt_id).await.unwrap();
        assert!(
            backend
                .wait_for_exit(plan.attempt_id, Duration::from_secs(2))
                .await
                .unwrap()
        );
        backend.cleanup(plan.attempt_id).await.unwrap();
    }

    #[tokio::test]
    async fn dedicated_ownership_fd_three_is_injected_and_eof_is_bounded() {
        let directory = TempDir::new().unwrap();
        let backend = UnixProcessBackend::new(credential_directory(&directory)).unwrap();
        let mut plan = plan(&directory);
        plan.ownership_channel = OwnershipChannel::DedicatedFd;
        plan.arguments = vec![
            "-c".into(),
            "test \"$NAVIGATOR_OWNERSHIP_FD\" = 3 && test -r /dev/fd/3 && cat <&3 >/dev/null"
                .into(),
        ];
        let evidence = backend.spawn(&plan, &[8; 32]).await.unwrap();
        assert_eq!(
            backend.inspect(plan.attempt_id, &evidence).await.unwrap(),
            IdentityObservation::Same
        );
        backend.revoke_ownership(plan.attempt_id).await.unwrap();
        assert!(
            backend
                .wait_for_exit(plan.attempt_id, Duration::from_secs(2))
                .await
                .unwrap()
        );
        backend.cleanup(plan.attempt_id).await.unwrap();
    }

    #[tokio::test]
    async fn terminal_pty_is_bounded_identity_checked_and_separate_from_ownership() {
        let directory = TempDir::new().unwrap();
        let backend = UnixProcessBackend::new(credential_directory(&directory)).unwrap();
        let mut plan = plan(&directory);
        plan.ownership_channel = OwnershipChannel::DedicatedFd;
        plan.process_io_mode = ProcessIoMode::TerminalPty;
        plan.arguments = vec![
            "-c".into(),
            "read line; printf 'PTY:%s\\n' \"$line\"; sleep 5".into(),
        ];
        let evidence = backend.spawn(&plan, &[7; 32]).await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        backend
            .write_terminal(plan.attempt_id, &evidence, b"hello\n", deadline)
            .await
            .unwrap();
        let mut observed = Vec::new();
        while !observed.windows(9).any(|window| window == b"PTY:hello") {
            observed.extend(
                backend
                    .read_terminal(plan.attempt_id, &evidence, 256, deadline)
                    .await
                    .unwrap(),
            );
        }
        assert!(
            backend
                .write_terminal(
                    plan.attempt_id,
                    &evidence,
                    &vec![0; UnixProcessBackend::MAX_TERMINAL_FRAME_BYTES + 1],
                    deadline,
                )
                .await
                .is_err()
        );
        let mut forged = evidence.clone();
        forged.creation_marker += 1;
        assert!(
            backend
                .read_terminal(plan.attempt_id, &forged, 1, deadline)
                .await
                .is_err()
        );
        backend.revoke_ownership(plan.attempt_id).await.unwrap();
    }

    #[tokio::test]
    async fn executable_path_replacement_fails_conservative_before_signal() {
        let directory = TempDir::new().unwrap();
        let executable = directory.path().join("driver");
        let original = std::fs::read("/bin/sh").unwrap();
        std::fs::write(&executable, &original).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let backend = UnixProcessBackend::new(credential_directory(&directory)).unwrap();
        let mut plan = plan(&directory);
        plan.program = executable.clone();
        let evidence = backend.spawn(&plan, &[5; 32]).await.unwrap();
        let replacement = directory.path().join("replacement");
        std::fs::write(&replacement, b"changed").unwrap();
        std::fs::rename(&replacement, &executable).unwrap();
        assert_eq!(
            backend.inspect(plan.attempt_id, &evidence).await.unwrap(),
            IdentityObservation::Mismatch
        );
        assert!(
            backend
                .force_stop_group(plan.attempt_id, &evidence)
                .await
                .is_err()
        );
        let restored = directory.path().join("restored");
        std::fs::write(&restored, original).unwrap();
        std::fs::rename(restored, &executable).unwrap();
        backend
            .force_stop_group(plan.attempt_id, &evidence)
            .await
            .unwrap();
        assert!(
            backend
                .wait_for_exit(plan.attempt_id, Duration::from_secs(2))
                .await
                .unwrap()
        );
        backend.cleanup(plan.attempt_id).await.unwrap();
    }

    #[tokio::test]
    async fn stubborn_descendant_keeps_group_live_until_verified_escalation() {
        let directory = TempDir::new().unwrap();
        let backend = UnixProcessBackend::new(credential_directory(&directory)).unwrap();
        let mut plan = plan(&directory);
        let ready = directory.path().join("group-ready");
        plan.environment
            .insert(OsString::from("READY_FILE"), ready.clone().into_os_string());
        plan.environment_allowlist
            .insert(OsString::from("READY_FILE"));
        plan.arguments = vec![
            "-c".into(),
            "trap '' TERM; (trap '' TERM; while :; do /bin/sleep 1; done) & printf ready > \"$READY_FILE\"; while :; do /bin/sleep 1; done"
                .into(),
        ];
        let evidence = backend.spawn(&plan, &[6; 32]).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !ready.is_file() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        backend
            .graceful_stop(plan.attempt_id, &evidence)
            .await
            .unwrap();
        assert!(
            !backend
                .wait_for_exit(plan.attempt_id, Duration::from_millis(50))
                .await
                .unwrap()
        );
        backend
            .force_stop_group(plan.attempt_id, &evidence)
            .await
            .unwrap();
        assert!(
            backend
                .wait_for_exit(plan.attempt_id, Duration::from_secs(2))
                .await
                .unwrap()
        );
        backend.cleanup(plan.attempt_id).await.unwrap();
    }
}
