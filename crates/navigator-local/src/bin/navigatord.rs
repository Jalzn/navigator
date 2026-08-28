use std::{collections::BTreeSet, path::PathBuf, sync::Arc, time::Duration};

use clap::Parser;
use navigator_local::{
    BootstrapCredential, DriverCatalogError, LocalArtifactStore, LocalNavigator, ServerConfig,
    TrustedDriverCatalog, build_catalog_runtime_components, load_or_create_host_id, serve,
    validate_socket_directory,
};
use navigator_store_api::LeaseDuration;
use navigator_store_sqlite::SqliteStore;
use tokio::sync::watch;

const DEFAULT_SHUTDOWN_TIMEOUT_MS: u64 = 10_000;
const MIN_CONFIGURED_RUNTIME_SHUTDOWN_MS: u64 = 5_100;

const fn configured_runtime_deadline_valid(timeout_ms: u64) -> bool {
    timeout_ms >= MIN_CONFIGURED_RUNTIME_SHUTDOWN_MS
}

#[derive(Parser)]
struct Args {
    #[arg(long)]
    database: PathBuf,
    #[arg(long)]
    socket: PathBuf,
    #[arg(long)]
    credential_file: PathBuf,
    #[arg(long, default_value_t = 30_000)]
    lease_ms: u64,
    #[arg(long, default_value_t = DEFAULT_SHUTDOWN_TIMEOUT_MS)]
    shutdown_timeout_ms: u64,
    /// Trusted JSON Driver catalog. Omission keeps execution fail-closed.
    #[arg(long, requires = "driver_entry")]
    driver_catalog: Option<PathBuf>,
    /// Trusted catalog entry selected by the daemon operator, never task input.
    #[arg(long, requires = "driver_catalog")]
    driver_entry: Vec<String>,
    /// Private short-path root for configured Driver process state.
    #[arg(long, requires = "driver_catalog")]
    driver_runtime: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    // Fail closed before host identity creation, migrations, artifact-root
    // creation, or runtime startup. `serve` repeats this check immediately
    // before binding so this early check does not weaken TOCTOU protection.
    validate_socket_directory(&args.socket)?;
    let selected_driver = if let Some(path) = &args.driver_catalog {
        if args.driver_entry.is_empty() {
            return Err(Box::<dyn std::error::Error>::from(
                DriverCatalogError::MissingCatalog,
            ));
        }
        let catalog = TrustedDriverCatalog::from_path(Some(path))?;
        let allowed = args.driver_entry.iter().cloned().collect::<BTreeSet<_>>();
        if allowed.len() != args.driver_entry.len() {
            return Err(Box::<dyn std::error::Error>::from(
                DriverCatalogError::InvalidCatalog,
            ));
        }
        for profile in &allowed {
            catalog.trusted_entry(profile)?;
        }
        Some((catalog, allowed))
    } else if !args.driver_entry.is_empty() {
        return Err(Box::<dyn std::error::Error>::from(
            DriverCatalogError::MissingCatalog,
        ));
    } else {
        None
    };
    if selected_driver.is_some() && !configured_runtime_deadline_valid(args.shutdown_timeout_ms) {
        return Err(Box::<dyn std::error::Error>::from(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "configured Driver runtime requires --shutdown-timeout-ms >= {MIN_CONFIGURED_RUNTIME_SHUTDOWN_MS}"
            ),
        )));
    }
    let credential = BootstrapCredential::from_file(&args.credential_file)?;
    let host_path = args.database.with_extension("host-id");
    let host_id = load_or_create_host_id(host_path)?;
    let lease_duration = LeaseDuration::from_millis(args.lease_ms)?;
    let store = Arc::new(SqliteStore::open(&args.database).await?);
    let artifact_root = args.database.with_extension("artifacts");
    let artifacts = Arc::new(LocalArtifactStore::new(store.clone(), artifact_root)?);
    let mut service = LocalNavigator::new(store.clone(), host_id, lease_duration)
        .with_artifact_controller(artifacts);
    if let Some((catalog, allowed_profiles)) = selected_driver {
        let runtime_root = args
            .driver_runtime
            .clone()
            .unwrap_or_else(|| args.database.with_extension("driver-runtime"));
        let runtime = build_catalog_runtime_components(
            store.clone(),
            host_id,
            catalog,
            allowed_profiles,
            runtime_root,
        )?;
        let inspector = Arc::clone(&runtime.recovery_inspector);
        let recovery_scheduler = Arc::clone(&runtime.permit_scheduler);
        service = service
            .with_recovery_runtime(inspector, recovery_scheduler)
            .with_configured_runtime(runtime)?;
    }
    let (shutdown, receiver) = watch::channel(false);
    tokio::spawn(async move {
        wait_for_signal().await;
        let _ = shutdown.send(true);
    });
    serve(
        service,
        credential,
        ServerConfig {
            socket_path: args.socket,
            shutdown_timeout: Duration::from_millis(args.shutdown_timeout_ms),
        },
        receiver,
    )
    .await?;
    Ok(())
}

#[cfg(unix)]
async fn wait_for_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate =
        signal(SignalKind::terminate()).expect("SIGTERM handler installation failed");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}

#[cfg(not(unix))]
async fn wait_for_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_close_deadline_has_supervisor_and_persistence_margin() {
        let args = Args::try_parse_from([
            "navigatord",
            "--database",
            "/tmp/navigator-test.db",
            "--socket",
            "/tmp/navigator-test.sock",
            "--credential-file",
            "/tmp/navigator-test.credential",
        ])
        .unwrap();
        assert_eq!(args.shutdown_timeout_ms, DEFAULT_SHUTDOWN_TIMEOUT_MS);
        assert!(
            Duration::from_millis(args.shutdown_timeout_ms)
                > Duration::from_secs(2) + Duration::from_secs(2) + Duration::from_millis(100)
        );
        assert!(args.shutdown_timeout_ms >= MIN_CONFIGURED_RUNTIME_SHUTDOWN_MS);
        assert!(!configured_runtime_deadline_valid(
            MIN_CONFIGURED_RUNTIME_SHUTDOWN_MS - 1
        ));
        assert!(configured_runtime_deadline_valid(
            MIN_CONFIGURED_RUNTIME_SHUTDOWN_MS
        ));
    }
}
