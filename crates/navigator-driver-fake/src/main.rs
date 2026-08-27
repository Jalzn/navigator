use std::{
    env, fs, io,
    io::Read,
    path::{Path, PathBuf},
    process::{self, Command, Stdio},
    thread,
};

#[cfg(unix)]
use std::{
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    time::Duration,
};

use navigator_driver_fake::{
    CONTROL_SOCKET_ENV, CREDENTIAL_FILE_ENV, EXIT_CRASH, Engine, JOURNAL_FILE_ENV,
    ProcessDirective, SCENARIO_FILE_ENV, read_frame, write_frame,
};
use navigator_driver_protocol::decode_envelope;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    record_process_identity()?;
    let credential =
        env::var(CREDENTIAL_FILE_ENV).or_else(|_| env::var("NAVIGATOR_CREDENTIAL_FILE"))?;
    let configured_journal = PathBuf::from(
        env::var(JOURNAL_FILE_ENV).or_else(|_| env::var("FAKE_DRIVER_JOURNAL_FILE"))?,
    );
    let journal = if configured_journal.is_dir() {
        let name = Path::new(&credential)
            .file_name()
            .ok_or("credential path has no file name")?;
        configured_journal.join(name).with_extension("journal.json")
    } else {
        configured_journal
    };
    let configured_scenario = PathBuf::from(
        env::var(SCENARIO_FILE_ENV).or_else(|_| env::var("FAKE_DRIVER_SCENARIO_FILE"))?,
    );
    let scenario = if configured_scenario.is_dir() {
        let name = Path::new(&credential)
            .file_name()
            .ok_or("credential path has no file name")?;
        configured_scenario
            .join(name)
            .with_extension("scenario.json")
    } else {
        configured_scenario
    };
    let configured_driver_id = env::var("NAVIGATOR_DRIVER_ID")
        .ok()
        .map(|value| decode_driver_id(&value))
        .transpose()?;
    let engine = Engine::open_with_driver_id(scenario, journal, credential, configured_driver_id)?;
    if let Some(delay) = env::var_os("FAKE_DRIVER_BEFORE_SOCKET_DELAY_MS") {
        let delay: u64 = delay.to_string_lossy().parse()?;
        if delay > 10_000 {
            return Err("fake Driver socket delay exceeds test bound".into());
        }
        thread::sleep(std::time::Duration::from_millis(delay));
    }
    if let Ok(socket) =
        env::var(CONTROL_SOCKET_ENV).or_else(|_| env::var("NAVIGATOR_CONTROL_SOCKET"))
    {
        #[cfg(unix)]
        if env::var_os("FAKE_DRIVER_RESTART_CHILD").is_some() {
            wait_for_socket_release(Path::new(&socket))?;
        }
        #[cfg(unix)]
        return run_uds(engine, Path::new(&socket));
        #[cfg(not(unix))]
        return Err("Unix control socket is unsupported on this platform".into());
    }
    let mut engine = engine;
    run_stdio(&mut engine)
}

fn record_process_identity() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(path) = env::var_os("FAKE_DRIVER_PID_FILE") {
        use std::io::Write;
        let mut output = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(output, "{}", process::id())?;
        output.sync_all()?;
    }
    Ok(())
}

#[cfg(unix)]
fn wait_for_socket_release(path: &Path) -> io::Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while fs::symlink_metadata(path).is_ok() {
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "old socket was not released",
            ));
        }
        thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

fn spawn_replacement() -> Result<(), Box<dyn std::error::Error>> {
    if env::var_os("FAKE_DRIVER_AUTO_RESTART").is_none() {
        return Ok(());
    }
    Command::new(env::current_exe()?)
        .env("FAKE_DRIVER_RESTART_CHILD", "1")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok(())
}

fn decode_driver_id(value: &str) -> Result<[u8; 16], Box<dyn std::error::Error>> {
    if value.len() != 32 {
        return Err("invalid configured Driver identity".into());
    }
    let mut output = [0_u8; 16];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid configured Driver identity")?;
    }
    if output.iter().all(|byte| *byte == 0) {
        return Err("invalid configured Driver identity".into());
    }
    Ok(output)
}

fn run_stdio(engine: &mut Engine) -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut output = io::stdout().lock();
    while let Some(bytes) = read_frame(&mut input)? {
        let envelope = decode_envelope(&bytes)?;
        let (response, directive) = engine.handle(&envelope, unix_millis())?;
        if let Some(response) = response {
            write_frame(&mut output, &response)?;
        }
        match directive {
            ProcessDirective::Continue => {}
            ProcessDirective::Exit | ProcessDirective::Disconnect => return Ok(()),
            ProcessDirective::Crash => {
                spawn_replacement()?;
                process::exit(EXIT_CRASH);
            }
            ProcessDirective::Hang => loop {
                thread::park();
            },
        }
    }
    Ok(())
}

#[cfg(unix)]
fn run_uds(engine: Engine, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    validate_socket_path(path)?;
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    let metadata = fs::symlink_metadata(path)?;
    let parent = fs::symlink_metadata(path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "control socket has no parent")
    })?)?;
    if metadata.uid() != parent.uid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "control socket ownership is inconsistent",
        )
        .into());
    }
    let _cleanup = SocketCleanup {
        path: path.to_path_buf(),
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    listener.set_nonblocking(true)?;
    let owner_lost = Arc::new(AtomicBool::new(false));
    let terminating = Arc::new(AtomicBool::new(false));
    let engine = Arc::new(Mutex::new(engine));
    let active = Arc::new(Mutex::new(Vec::<(u64, UnixStream)>::new()));
    let active_on_eof = Arc::clone(&active);
    let owner_lost_on_eof = Arc::clone(&owner_lost);
    let terminating_on_eof = Arc::clone(&terminating);
    let engine_on_eof = Arc::clone(&engine);
    thread::spawn(move || {
        let mut stdin = io::stdin();
        let mut byte = [0_u8; 1];
        while stdin.read(&mut byte).is_ok_and(|count| count != 0) {}
        // Linearize ownership loss against effect admission on every channel.
        // An already-admitted Engine transition completes before this guard;
        // no later transition can pass the terminating check under the guard.
        let engine_guard = engine_on_eof.lock().expect("fake Driver engine poisoned");
        terminating_on_eof.store(true, Ordering::Release);
        drop(engine_guard);
        owner_lost_on_eof.store(true, Ordering::Release);
        for (_, stream) in active_on_eof
            .lock()
            .expect("active sockets poisoned")
            .iter()
        {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    });
    let next_connection = AtomicU64::new(1);
    let (directive_tx, directive_rx) = mpsc::channel();
    loop {
        if owner_lost.load(Ordering::Acquire)
            || matches!(directive_rx.try_recv(), Ok(ProcessDirective::Exit))
        {
            return Ok(());
        }
        let (stream, _) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        if stream.set_nonblocking(false).is_err()
            || stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .is_err()
        {
            continue;
        }
        let connection_id = next_connection.fetch_add(1, Ordering::Relaxed);
        active
            .lock()
            .expect("active sockets poisoned")
            .push((connection_id, stream.try_clone()?));
        let active_connection = Arc::clone(&active);
        let connection_engine = Arc::clone(&engine);
        let connection_owner_lost = Arc::clone(&owner_lost);
        let connection_terminating = Arc::clone(&terminating);
        let connection_directive = directive_tx.clone();
        let socket_path = path.to_path_buf();
        thread::spawn(move || {
            serve_uds_connection(
                stream,
                connection_id,
                &connection_engine,
                &active_connection,
                &connection_owner_lost,
                &connection_terminating,
                &connection_directive,
                &socket_path,
            );
        });
    }
}

#[cfg(unix)]
#[expect(
    clippy::too_many_arguments,
    reason = "connection lifecycle and process-wide termination remain explicit"
)]
fn serve_uds_connection(
    mut stream: UnixStream,
    connection_id: u64,
    engine: &Arc<Mutex<Engine>>,
    active: &Arc<Mutex<Vec<(u64, UnixStream)>>>,
    owner_lost: &Arc<AtomicBool>,
    terminating: &Arc<AtomicBool>,
    directive_tx: &mpsc::Sender<ProcessDirective>,
    socket_path: &Path,
) {
    while let Ok(Some(bytes)) = read_frame(&mut stream) {
        if terminating.load(Ordering::Acquire) {
            break;
        }
        let Ok(envelope) = decode_envelope(&bytes) else {
            break;
        };
        let handled = {
            let mut engine = engine.lock().expect("fake Driver engine poisoned");
            if terminating.load(Ordering::Acquire) {
                break;
            }
            let handled = engine.handle(&envelope, unix_millis());
            if handled.as_ref().is_ok_and(|(_, directive)| {
                matches!(
                    directive,
                    ProcessDirective::Exit | ProcessDirective::Crash | ProcessDirective::Hang
                )
            }) {
                terminating.store(true, Ordering::Release);
            }
            handled
        };
        let Ok((response, directive)) = handled else {
            break;
        };
        if response
            .as_ref()
            .is_some_and(|response| write_frame(&mut stream, response).is_err())
        {
            break;
        }
        match directive {
            ProcessDirective::Continue => {}
            ProcessDirective::Exit => {
                let _ = directive_tx.send(ProcessDirective::Exit);
                break;
            }
            ProcessDirective::Disconnect => break,
            ProcessDirective::Crash => {
                let _ = fs::remove_file(socket_path);
                let _ = spawn_replacement();
                process::exit(EXIT_CRASH);
            }
            ProcessDirective::Hang => {
                while !owner_lost.load(Ordering::Acquire) {
                    thread::sleep(Duration::from_millis(20));
                }
                break;
            }
        }
    }
    active
        .lock()
        .expect("active sockets poisoned")
        .retain(|(id, _)| *id != connection_id);
}

#[cfg(unix)]
fn validate_socket_path(path: &Path) -> io::Result<()> {
    if fs::symlink_metadata(path).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "control socket path exists",
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "control socket has no parent")
    })?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "control socket parent is unsafe",
        ));
    }
    Ok(())
}

#[cfg(unix)]
struct SocketCleanup {
    path: PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl Drop for SocketCleanup {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(i64::MAX, |duration| {
            i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
        })
}
