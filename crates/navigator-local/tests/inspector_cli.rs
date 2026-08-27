#![cfg(unix)]

use std::{os::unix::fs::PermissionsExt, process::Stdio, sync::Arc, time::Duration};

use navigator_consumer_protocol::{
    CAPABILITY_OPERATIONAL_PROJECTIONS_V1, CURRENT_MAJOR, CURRENT_MINOR, v1,
};
use navigator_domain::{HostId, SessionId};
use navigator_local::{
    AUTHENTICATION_HEADER, BootstrapCredential, LocalNavigator, ServerConfig, current_metadata,
    serve,
};
use navigator_store_api::{LeaseDuration, ProjectionStore};
use navigator_store_sqlite::SqliteStore;
use tempfile::TempDir;
use tokio::io::AsyncReadExt as _;
use tokio::sync::watch;
use tonic::{Request, metadata::MetadataValue, transport::Endpoint};
use uuid::Uuid;

fn authenticated<T>(value: T) -> Request<T> {
    let mut request = Request::new(value);
    request.metadata_mut().insert(
        AUTHENTICATION_HEADER,
        MetadataValue::try_from("inspector-cli-test").unwrap(),
    );
    request
}

fn root_template() -> v1::RootTemplateSpecification {
    v1::RootTemplateSpecification {
        template_id: Uuid::from_u128(81_010).as_bytes().to_vec(),
        role: "inspected-root".into(),
        driver_id: Uuid::from_u128(81_011).as_bytes().to_vec(),
        required_capabilities: vec![v1::DriverCapabilityRequirement {
            capability: "durable.acceptance".into(),
            minimum_version: 1,
            parameters: vec![],
        }],
        trusted_configuration: Some(v1::TrustedTemplateConfiguration {
            base_instructions: "inspect safely".into(),
            secret_names: vec![],
        }),
        resources: Some(v1::ParticipantResourceBounds {
            memory_bytes: 1 << 20,
            cpu_millis: 1_000,
            max_concurrent_operations: 1,
        }),
        input_schema: Some(v1::InputSchema { fields: vec![] }),
        authority_profile: None,
    }
}

async fn wait_for_socket(path: &std::path::Path) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !path.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

async fn wait_for_output(mut child: tokio::process::Child, context: &str) -> std::process::Output {
    let mut stdout = child.stdout.take().expect("stdout was not piped");
    let mut stderr = child.stderr.take().expect("stderr was not piped");
    let stdout_reader = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).await.unwrap();
        bytes
    });
    let stderr_reader = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).await.unwrap();
        bytes
    });
    let status =
        if let Ok(result) = tokio::time::timeout(Duration::from_secs(3), child.wait()).await {
            result.unwrap()
        } else {
            child.kill().await.unwrap();
            child.wait().await.unwrap();
            stdout_reader.await.unwrap();
            stderr_reader.await.unwrap();
            panic!("{context} hung");
        };
    std::process::Output {
        status,
        stdout: stdout_reader.await.unwrap(),
        stderr: stderr_reader.await.unwrap(),
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the subprocess UDS fixture is intentionally explicit"
)]
async fn navigatorctl_inspect_is_finite_noninteractive_and_bound_to_prior_negotiation() {
    let directory = TempDir::new().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let database = directory.path().join("inspector.db");
    let socket = directory.path().join("navigator.sock");
    let credential_file = directory.path().join("credential");
    std::fs::write(&credential_file, b"inspector-cli-test").unwrap();
    std::fs::set_permissions(&credential_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let store = Arc::new(SqliteStore::open(&database).await.unwrap());
    let service = LocalNavigator::new(
        store.clone(),
        HostId::from_uuid(Uuid::from_u128(81_001)).unwrap(),
        LeaseDuration::from_millis(60_000).unwrap(),
    )
    .with_operational_projections();
    let (shutdown, receiver) = watch::channel(false);
    let server = tokio::spawn(serve(
        service,
        BootstrapCredential::from_bytes(b"inspector-cli-test".to_vec()).unwrap(),
        ServerConfig {
            socket_path: socket.clone(),
            shutdown_timeout: Duration::from_secs(2),
        },
        receiver,
    ));
    wait_for_socket(&socket).await;
    let channel = Endpoint::from_shared(format!("unix:{}", socket.display()))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = v1::navigator_consumer_client::NavigatorConsumerClient::new(channel);
    let negotiation = client
        .negotiate(authenticated(v1::NegotiateRequest {
            minimum_version: Some(v1::ProtocolVersion { major: 1, minor: 2 }),
            maximum_version: Some(v1::ProtocolVersion { major: 1, minor: 2 }),
            capabilities: vec![
                "session.lifecycle.v1".into(),
                "events.replay.v1".into(),
                CAPABILITY_OPERATIONAL_PROJECTIONS_V1.into(),
                "operation.execution.v1".into(),
            ],
        }))
        .await
        .unwrap()
        .into_inner();
    let Some(v1::negotiate_response::Outcome::Negotiated(negotiated)) = negotiation.outcome else {
        panic!("negotiation failed");
    };
    let negotiation_id = Uuid::from_slice(&negotiated.negotiation_id).unwrap();
    let negotiation_file = directory.path().join("negotiation.token");
    std::fs::write(&negotiation_file, format!("{negotiation_id}\n")).unwrap();
    std::fs::set_permissions(&negotiation_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let session = Uuid::from_u128(81_003);
    let opened = client
        .open_session(authenticated(v1::OpenSessionRequest {
            metadata: Some(current_metadata(
                negotiated.negotiation_id,
                &["session.lifecycle.v1"],
            )),
            request_id: Uuid::from_u128(81_004).as_bytes().to_vec(),
            session_id: session.as_bytes().to_vec(),
            consumer_key: "inspector-cli".into(),
            compatibility_identity: vec![],
            root_template: Some(root_template()),
            compatible_templates: vec![],
            configuration_identity: negotiated.configuration_identity,
            mode: v1::SessionOpenMode::Unspecified.into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(matches!(
        opened.outcome,
        Some(v1::open_session_response::Outcome::Snapshot(_))
    ));
    let unbound = client
        .negotiate(authenticated(v1::NegotiateRequest {
            minimum_version: Some(v1::ProtocolVersion { major: 1, minor: 2 }),
            maximum_version: Some(v1::ProtocolVersion { major: 1, minor: 2 }),
            capabilities: vec![
                "session.lifecycle.v1".into(),
                "events.replay.v1".into(),
                CAPABILITY_OPERATIONAL_PROJECTIONS_V1.into(),
            ],
        }))
        .await
        .unwrap()
        .into_inner();
    let Some(v1::negotiate_response::Outcome::Negotiated(unbound)) = unbound.outcome else {
        panic!("unbound negotiation failed");
    };
    assert_ne!(
        unbound.negotiation_id.as_slice(),
        negotiation_id.as_bytes(),
        "unbound fixture was deduplicated with the bound negotiation"
    );
    let unbound_file = directory.path().join("unbound-negotiation.token");
    std::fs::write(
        &unbound_file,
        format!("{}\n", Uuid::from_slice(&unbound.negotiation_id).unwrap()),
    )
    .unwrap();
    std::fs::set_permissions(&unbound_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if store
                .rebuild_projection(SessionId::from_uuid(session).unwrap())
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("projection rebuild remained unavailable");
    let generation: i64 =
        sqlx::query_scalar("SELECT generation FROM projection_heads WHERE session_id=?")
            .bind(session.to_string())
            .fetch_one(store.pool())
            .await
            .unwrap();
    for (item_key, sort_key) in [
        ("cli-first-row", "\u{1}-cli-first-row"),
        ("cli-resume-row", "\u{2}-cli-resume-row"),
    ] {
        sqlx::query("INSERT INTO projection_rows(session_id,generation,view,item_key,sort_key,data) VALUES(?,?,'session_tree',?,?,?)")
            .bind(session.to_string())
            .bind(generation)
            .bind(item_key)
            .bind(sort_key)
            .bind(r#"{"label":"界界界界界界界界"}"#.as_bytes())
            .execute(store.pool())
            .await
            .unwrap();
    }

    let binary = env!("CARGO_BIN_EXE_navigatorctl");
    let mut child = std::process::Command::new(binary)
        .args([
            "--socket",
            socket.to_str().unwrap(),
            "--credential-file",
            credential_file.to_str().unwrap(),
            "--negotiation-id-file",
            negotiation_file.to_str().unwrap(),
            "inspect",
            "--session-id",
            &session.to_string(),
            "--consumer-key",
            "inspector-cli",
            "--page-size",
            "1",
            "--max-pages",
            "1",
            "--recent-events",
            "2",
            "--max-value-bytes",
            "16",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let status = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("non-interactive inspector hung");
    assert!(status.success());
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("PROJECTION_VIEW_SESSION_TREE"));
    assert!(stdout.contains("recent_events"));
    assert!(stdout.contains("resume_token="));
    assert!(stdout.contains("cli-first-row"));
    assert!(
        stdout.contains('…'),
        "first multibyte value was not truncated"
    );
    assert!(std::str::from_utf8(stdout.as_bytes()).is_ok());
    assert!(stdout.len() < 64 * 1024, "output must remain bounded");
    let token = stdout
        .lines()
        .find_map(|line| line.split_once("resume_token=").map(|(_, token)| token))
        .expect("first invocation did not expose a resume token");
    let first_item = stdout
        .lines()
        .find(|line| line.starts_with("  ") && !line.contains("resume_token="))
        .expect("first invocation did not render an item")
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();
    let mut resumed_child = std::process::Command::new(binary)
        .args([
            "--socket",
            socket.to_str().unwrap(),
            "--credential-file",
            credential_file.to_str().unwrap(),
            "--negotiation-id-file",
            negotiation_file.to_str().unwrap(),
            "inspect",
            "--session-id",
            &session.to_string(),
            "--consumer-key",
            "inspector-cli",
            "--page-size",
            "1",
            "--resume-view",
            "session_tree",
            "--resume-token",
            token,
            "--recent-events",
            "0",
            "--max-value-bytes",
            "16",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(status) = resumed_child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("resumed inspector hung");
    let resumed_output = resumed_child.wait_with_output().unwrap();
    let resumed_stdout = String::from_utf8(resumed_output.stdout).unwrap();
    assert!(resumed_stdout.contains("cli-resume-row"));
    assert!(!resumed_stdout.lines().any(|line| {
        line.starts_with("  ") && line.split_whitespace().next() == Some(first_item.as_str())
    }));
    assert!(
        resumed_stdout.contains('…'),
        "multibyte value was not truncated"
    );
    assert!(resumed_stdout.len() < 4 * 1024);
    for rendered in [&stdout, &resumed_stdout] {
        let value = rendered
            .lines()
            .find(|line| line.starts_with("  cli-"))
            .and_then(|line| line.trim_start().split_once(' '))
            .map(|(_, value)| value)
            .expect("CLI did not render the multibyte fixture row");
        let prefix = value.strip_suffix('…').expect("fixture must be truncated");
        assert!(prefix.len() <= 16, "truncated prefix exceeded byte bound");
        assert!(prefix.is_char_boundary(prefix.len()));
    }
    assert!(
        !stdout
            .lines()
            .filter(|line| line.starts_with("event id="))
            .collect::<Vec<_>>()
            .is_empty()
    );

    let invalid = std::process::Command::new(binary)
        .args([
            "--socket",
            socket.to_str().unwrap(),
            "--credential-file",
            credential_file.to_str().unwrap(),
            "--negotiation-id-file",
            negotiation_file.to_str().unwrap(),
            "inspect",
            "--session-id",
            &session.to_string(),
            "--consumer-key",
            "inspector-cli",
            "--page-size",
            "129",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    let invalid_runtime_bound = std::process::Command::new(binary)
        .args([
            "--socket",
            socket.to_str().unwrap(),
            "--credential-file",
            credential_file.to_str().unwrap(),
            "--negotiation-id-file",
            negotiation_file.to_str().unwrap(),
            "inspect",
            "--session-id",
            &session.to_string(),
            "--consumer-key",
            "inspector-cli",
            "--max-pages",
            "0",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(invalid_runtime_bound.status.code(), Some(2));

    for negotiation_arguments in [
        Vec::<&str>::new(),
        vec!["--negotiation-id-file", unbound_file.to_str().unwrap()],
    ] {
        let mut command = tokio::process::Command::new(binary);
        command
            .args([
                "--socket",
                socket.to_str().unwrap(),
                "--credential-file",
                credential_file.to_str().unwrap(),
            ])
            .args(negotiation_arguments)
            .args([
                "inspect",
                "--session-id",
                &session.to_string(),
                "--consumer-key",
                "inspector-cli",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let rejected = wait_for_output(command.spawn().unwrap(), "rejected inspector").await;
        assert!(!rejected.status.success());
        assert!(
            rejected.stdout.is_empty(),
            "rejected inspector leaked rows/events"
        );
    }

    for (flag, value) in [
        ("--max-pages", "129"),
        ("--max-value-bytes", "15"),
        ("--max-value-bytes", "4097"),
        ("--recent-events", "129"),
    ] {
        let rejected = std::process::Command::new(binary)
            .args([
                "--socket",
                socket.to_str().unwrap(),
                "--credential-file",
                credential_file.to_str().unwrap(),
                "--negotiation-id-file",
                negotiation_file.to_str().unwrap(),
                "inspect",
                "--session-id",
                &session.to_string(),
                "--consumer-key",
                "inspector-cli",
                flag,
                value,
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            !rejected.status.success(),
            "accepted invalid {flag}={value}"
        );
        assert!(
            rejected.stdout.is_empty(),
            "invalid bound leaked rows/events"
        );
    }

    shutdown.send(true).unwrap();
    assert!(server.await.unwrap().is_ok());
    assert_eq!(CURRENT_MAJOR, 1);
    assert_eq!(CURRENT_MINOR, 2);
}
