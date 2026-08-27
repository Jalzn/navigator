use std::{
    fs::OpenOptions,
    io::{Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};
use navigator_consumer_protocol::v1::{
    self, close_session_response, negotiate_response, open_session_response, read_events_response,
    snapshot_response, subscribe_events_response,
};
use navigator_local::{BootstrapCredential, LocalClient};
use uuid::Uuid;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    socket: PathBuf,
    #[arg(long)]
    credential_file: PathBuf,
    /// Owner-only file used to create or resume the exact Consumer-bound
    /// negotiation without exposing bearer material in argv or stdout. Tokens
    /// expire when navigatord restarts; renegotiate into a new file, then replay
    /// Open to bind that new token to the durable Consumer.
    #[arg(long, global = true)]
    negotiation_id_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Negotiate,
    Open {
        #[arg(long)]
        request_id: Uuid,
        #[arg(long)]
        session_id: Uuid,
        #[arg(long)]
        consumer_key: String,
        #[arg(long)]
        template_id: Uuid,
        #[arg(long)]
        driver_id: Uuid,
        #[arg(long)]
        role: String,
        #[arg(long)]
        base_instructions: String,
        #[arg(long)]
        expected_compatibility: Option<String>,
    },
    Snapshot {
        #[arg(long)]
        session_id: Uuid,
    },
    Close {
        #[arg(long)]
        request_id: Uuid,
        #[arg(long)]
        session_id: Uuid,
    },
    Events {
        #[arg(long)]
        session_id: Uuid,
        #[arg(long, default_value_t = 0)]
        after: u64,
        #[arg(long, default_value_t = 1)]
        count: usize,
    },
    /// Print a bounded, read-only operational snapshot for scripts or a separate terminal.
    Inspect {
        #[arg(long)]
        session_id: Uuid,
        #[arg(long)]
        consumer_key: String,
        #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u32).range(1..=128))]
        page_size: u32,
        #[arg(long, default_value_t = 16, value_parser = parse_max_pages)]
        max_pages: usize,
        #[arg(long, default_value_t = 512)]
        max_value_bytes: usize,
        #[arg(long, default_value_t = 20)]
        recent_events: usize,
        /// Resume only this view (`session_tree`, `active_work`, etc.).
        #[arg(long, requires = "resume_token")]
        resume_view: Option<String>,
        /// Opaque token printed by an earlier bounded inspection.
        #[arg(long, requires = "resume_view")]
        resume_token: Option<String>,
    },
}

#[tokio::main]
#[expect(
    clippy::too_many_lines,
    reason = "CLI dispatch keeps subcommand effects explicit"
)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let credential = BootstrapCredential::from_file(args.credential_file)?;
    let mut client = LocalClient::connect(args.socket, &credential).await?;
    if !matches!(args.command, Command::Negotiate) {
        let path = args
            .negotiation_id_file
            .as_deref()
            .ok_or("this command requires --negotiation-id-file; run negotiate first")?;
        client.select_bound_negotiation(read_negotiation_id(path)?);
    }
    match args.command {
        Command::Negotiate => {
            let path = args
                .negotiation_id_file
                .as_deref()
                .ok_or("negotiate requires --negotiation-id-file for protected token handoff")?;
            persist_negotiation(client.negotiate().await?, path)?;
        }
        Command::Open {
            request_id,
            session_id,
            consumer_key,
            template_id,
            driver_id,
            role,
            base_instructions,
            expected_compatibility,
        } => {
            let compatibility = expected_compatibility
                .as_deref()
                .map(decode_compatibility)
                .transpose()?;
            let root_template = v1::RootTemplateSpecification {
                template_id: template_id.as_bytes().to_vec(),
                role,
                driver_id: driver_id.as_bytes().to_vec(),
                required_capabilities: Vec::new(),
                trusted_configuration: Some(v1::TrustedTemplateConfiguration {
                    base_instructions,
                    secret_names: Vec::new(),
                }),
                resources: Some(v1::ParticipantResourceBounds {
                    memory_bytes: 64 * 1024 * 1024,
                    cpu_millis: 1_000,
                    max_concurrent_operations: 1,
                }),
                input_schema: Some(v1::InputSchema { fields: Vec::new() }),
                authority_profile: None,
            };
            print_open(
                client
                    .open(
                        request_id,
                        session_id,
                        consumer_key,
                        root_template,
                        compatibility,
                    )
                    .await?,
            );
        }
        Command::Snapshot { session_id } => {
            print_snapshot_response(client.snapshot(session_id).await?);
        }
        Command::Close {
            request_id,
            session_id,
        } => print_close(client.close(request_id, session_id).await?),
        Command::Events {
            session_id,
            after,
            count,
        } => {
            let mut stream = client.events(session_id, after).await?;
            for _ in 0..count {
                let Some(response) = stream.message().await? else {
                    fatal("event stream ended before requested count");
                };
                match response.outcome {
                    Some(subscribe_events_response::Outcome::Event(event)) => print_event(&event),
                    Some(subscribe_events_response::Outcome::Failure(error)) => {
                        print_failure(&error);
                    }
                    None => fatal("event response has no outcome"),
                }
            }
        }
        Command::Inspect {
            session_id,
            consumer_key,
            page_size,
            max_pages,
            max_value_bytes,
            recent_events,
            resume_view,
            resume_token,
        } => {
            inspect(
                &mut client,
                session_id,
                consumer_key,
                page_size,
                max_pages,
                max_value_bytes,
                recent_events,
                resume_view,
                resume_token,
            )
            .await?;
        }
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the bounded inspector keeps its CLI inputs and seven-view loop explicit"
)]
async fn inspect(
    client: &mut LocalClient,
    session_id: Uuid,
    consumer_key: String,
    page_size: u32,
    max_pages: usize,
    max_value_bytes: usize,
    recent_events: usize,
    resume_view: Option<String>,
    resume_token: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use v1::read_projection_response::Outcome;
    if !(1..=128).contains(&max_pages)
        || !(16..=4096).contains(&max_value_bytes)
        || recent_events > 128
    {
        return Err("inspector bounds are invalid".into());
    }
    let mut source_head = 0;
    let all_views = [
        v1::ProjectionView::SessionTree,
        v1::ProjectionView::ActiveWork,
        v1::ProjectionView::Delivery,
        v1::ProjectionView::Approval,
        v1::ProjectionView::Recovery,
        v1::ProjectionView::Capacity,
        v1::ProjectionView::Failure,
    ];
    let selected_view = resume_view
        .as_deref()
        .map(parse_projection_view)
        .transpose()?;
    for view in all_views
        .into_iter()
        .filter(|view| selected_view.is_none_or(|selected| selected == *view))
    {
        let mut token = resume_token.clone().unwrap_or_default();
        for _ in 0..max_pages {
            let response = client
                .read_projection(
                    session_id,
                    consumer_key.clone(),
                    view,
                    page_size,
                    token.clone(),
                )
                .await?;
            let page = match response.outcome {
                Some(Outcome::Page(page)) => page,
                Some(Outcome::Failure(error)) => {
                    print_failure(&error);
                }
                None => fatal("projection response has no outcome"),
            };
            println!(
                "view={} generation={} checkpoint={} source_head={}",
                view.as_str_name(),
                page.generation,
                page.checkpoint_position
                    .map_or_else(|| "-".into(), |v| v.to_string()),
                page.source_head_position
                    .map_or_else(|| "-".into(), |v| v.to_string()),
            );
            source_head = source_head.max(page.source_head_position.unwrap_or(0));
            for item in page.items {
                let rendered = String::from_utf8_lossy(&item.redacted_json);
                println!(
                    "  {} {}",
                    item.key,
                    truncate_utf8(&rendered, max_value_bytes)
                );
            }
            token = page.next_page_token;
            if token.is_empty() {
                break;
            }
        }
        if !token.is_empty() {
            println!("  … page limit reached; resume_token={token}");
        }
    }
    if recent_events != 0 {
        println!("recent_events");
        let mut after = source_head.saturating_sub(recent_events as u64);
        let mut remaining = recent_events;
        while remaining != 0 {
            let page_size = u32::try_from(remaining.min(128)).expect("bounded page size");
            let response = client.read_events(session_id, after, page_size).await?;
            match response.outcome {
                Some(read_events_response::Outcome::Page(page)) => {
                    let count = page.events.len();
                    for event in page.events {
                        if event.position <= after {
                            return Err("event resume cursor regressed".into());
                        }
                        after = event.position;
                        print_event(&event);
                    }
                    remaining = remaining.saturating_sub(count);
                    if !page.has_more || count == 0 {
                        break;
                    }
                }
                Some(read_events_response::Outcome::Failure(error)) => {
                    print_failure(&error);
                }
                None => return Err("event response has no outcome".into()),
            }
        }
    }
    Ok(())
}

fn parse_projection_view(value: &str) -> Result<v1::ProjectionView, String> {
    match value {
        "session_tree" => Ok(v1::ProjectionView::SessionTree),
        "active_work" => Ok(v1::ProjectionView::ActiveWork),
        "delivery" => Ok(v1::ProjectionView::Delivery),
        "approval" => Ok(v1::ProjectionView::Approval),
        "recovery" => Ok(v1::ProjectionView::Recovery),
        "capacity" => Ok(v1::ProjectionView::Capacity),
        "failure" => Ok(v1::ProjectionView::Failure),
        _ => Err("resume-view is unknown".to_owned()),
    }
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

fn parse_max_pages(value: &str) -> Result<usize, String> {
    let value = value
        .parse::<usize>()
        .map_err(|_| "max-pages must be an integer".to_owned())?;
    (1..=128)
        .contains(&value)
        .then_some(value)
        .ok_or_else(|| "max-pages must be between 1 and 128".to_owned())
}

fn decode_compatibility(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.is_ascii() {
        return Err("compatibility must contain 64 hexadecimal characters".into());
    }
    let mut output = [0; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "compatibility is not hexadecimal")?;
    }
    Ok(output)
}

fn persist_negotiation(
    response: v1::NegotiateResponse,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    match response.outcome {
        Some(negotiate_response::Outcome::Negotiated(value)) => {
            let version = value.protocol_version.unwrap_or_default();
            let id = Uuid::from_slice(&value.negotiation_id)
                .map_err(|_| "daemon returned an invalid negotiation identity")?;
            write_negotiation_id(path, id)?;
            println!(
                "negotiated version={}.{} capabilities={} token_file={}",
                version.major,
                version.minor,
                value.capabilities.join(","),
                path.display()
            );
        }
        Some(negotiate_response::Outcome::Failure(value)) => print_failure(&value),
        None => fatal("negotiation response has no outcome"),
    }
    Ok(())
}

fn validate_private_parent(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let parent = path
        .parent()
        .ok_or("negotiation token path has no parent")?;
    let metadata = std::fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err("negotiation token parent must be an owner-only directory".into());
    }
    Ok(())
}

fn write_negotiation_id(
    path: &Path,
    negotiation_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_private_parent(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    writeln!(file, "{negotiation_id}")?;
    file.sync_all()?;
    Ok(())
}

fn read_negotiation_id(path: &Path) -> Result<Uuid, Box<dyn std::error::Error>> {
    validate_private_parent(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.len() > 64
    {
        return Err("negotiation token file must be owner-only and regular".into());
    }
    let mut text = String::new();
    file.take(65).read_to_string(&mut text)?;
    Ok(Uuid::parse_str(text.trim_end_matches(['\r', '\n']))?)
}

fn print_open(response: v1::OpenSessionResponse) {
    match response.outcome {
        Some(open_session_response::Outcome::Snapshot(value)) => print_snapshot(&value),
        Some(open_session_response::Outcome::Failure(value)) => print_failure(&value),
        None => fatal("open response has no outcome"),
    }
}

fn print_snapshot_response(response: v1::SnapshotResponse) {
    match response.outcome {
        Some(snapshot_response::Outcome::Snapshot(value)) => print_snapshot(&value),
        Some(snapshot_response::Outcome::Failure(value)) => print_failure(&value),
        None => fatal("snapshot response has no outcome"),
    }
}

fn print_close(response: v1::CloseSessionResponse) {
    match response.outcome {
        Some(close_session_response::Outcome::Snapshot(value)) => print_snapshot(&value),
        Some(close_session_response::Outcome::Failure(value)) => print_failure(&value),
        None => fatal("close response has no outcome"),
    }
}

fn print_snapshot(value: &v1::SessionSnapshot) {
    let id =
        Uuid::from_slice(&value.session_id).map_or_else(|_| "invalid".into(), |id| id.to_string());
    let status =
        v1::SessionStatus::try_from(value.status).map_or("unknown", |value| value.as_str_name());
    println!(
        "session id={id} status={status} revision={}",
        value.revision
    );
}

fn print_event(value: &v1::SessionEvent) {
    let id =
        Uuid::from_slice(&value.event_id).map_or_else(|_| "invalid".into(), |id| id.to_string());
    println!(
        "event id={id} position={} revision={} type={}",
        value.position, value.revision, value.event_type
    );
}

fn print_failure(value: &v1::Failure) -> ! {
    let code = v1::FailureCode::try_from(value.code).map_or("unknown", |value| value.as_str_name());
    eprintln!("failure code={code} message={}", value.message);
    std::process::exit(2);
}

fn fatal(message: &str) -> ! {
    eprintln!("failure code=internal message={message}");
    std::process::exit(2);
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use super::{read_negotiation_id, truncate_utf8, write_negotiation_id};
    use uuid::Uuid;

    #[test]
    fn truncation_is_bounded_and_never_splits_unicode() {
        assert_eq!(truncate_utf8("abc", 3), "abc");
        assert_eq!(truncate_utf8("aé日z", 4), "aé…");
        assert!(truncate_utf8(&"界".repeat(10_000), 512).len() <= 515);
    }

    #[test]
    fn negotiation_token_file_is_owner_only_bounded_and_never_follows_symlinks() {
        let directory = tempfile::TempDir::new().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let token = directory.path().join("negotiation.token");
        let id = Uuid::from_u128(42);
        write_negotiation_id(&token, id).unwrap();
        assert_eq!(read_negotiation_id(&token).unwrap(), id);
        assert_eq!(
            std::fs::metadata(&token).unwrap().permissions().mode() & 0o777,
            0o600
        );

        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_negotiation_id(&token).is_err());
        std::fs::remove_file(&token).unwrap();
        let target = directory.path().join("target");
        std::fs::write(&target, id.to_string()).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &token).unwrap();
        assert!(read_negotiation_id(&token).is_err());
        assert!(write_negotiation_id(&token, id).is_err());

        std::fs::remove_file(&token).unwrap();
        std::fs::write(&token, "not-a-token").unwrap();
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_negotiation_id(&token).is_err());

        let unsafe_directory = directory.path().join("unsafe");
        std::fs::create_dir(&unsafe_directory).unwrap();
        std::fs::set_permissions(&unsafe_directory, std::fs::Permissions::from_mode(0o755))
            .unwrap();
        assert!(write_negotiation_id(&unsafe_directory.join("token"), id).is_err());
    }
}
