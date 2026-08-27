use std::{
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use navigator_domain::{
    ArtifactDigest, ArtifactId, ArtifactMediaType, ArtifactSnapshot, FencingEpoch, HostId,
    MAX_ARTIFACT_BYTES, OperationId, ParticipantId, RequestId, SessionId, Timestamp,
};
use navigator_store_api::{
    ArtifactAccess, ArtifactStore, CapacityResource, CapacityStore, DeleteArtifact, EraseArtifact,
    PublishArtifact, RequestContext, ReserveCapacity, StoreError,
};
use nix::{
    fcntl::{Flock, FlockArg},
    libc::O_NOFOLLOW,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn derived_reservation_id(request_id: RequestId, domain: u8) -> Result<RequestId, StoreError> {
    let mut bytes = *request_id.as_uuid().as_bytes();
    bytes[15] ^= domain;
    RequestId::from_uuid(uuid::Uuid::from_bytes(bytes)).map_err(|_| StoreError::Invalid)
}

#[derive(Debug, Error)]
pub enum LocalArtifactError {
    #[error("artifact filesystem boundary rejected the request")]
    Invalid,
    #[error("artifact exceeds the configured size bound")]
    Oversize,
    #[error("artifact content does not match its declared identity")]
    Integrity,
    #[error("artifact metadata store rejected the request")]
    Store(#[from] StoreError),
    #[error("artifact filesystem is unavailable")]
    Io(#[from] io::Error),
}

pub struct ArtifactWrite {
    pub request_id: RequestId,
    pub caller: HostId,
    pub session_id: SessionId,
    pub epoch: FencingEpoch,
    pub artifact_id: ArtifactId,
    pub creator_participant_id: ParticipantId,
    pub creator_operation_id: OperationId,
    pub media_type: ArtifactMediaType,
    pub expected_size: u64,
    pub expected_digest: ArtifactDigest,
    pub retention_until: Timestamp,
}

pub struct LocalArtifactStore<S> {
    metadata: Arc<S>,
    root: PathBuf,
    _root_lock: Flock<std::fs::File>,
}

impl<S> LocalArtifactStore<S>
where
    S: ArtifactStore + CapacityStore + 'static,
{
    pub fn new(metadata: Arc<S>, root: impl Into<PathBuf>) -> Result<Self, LocalArtifactError> {
        let root = root.into();
        match std::fs::create_dir(&root) {
            Ok(()) => std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        validate_owned_directory(&root)?;
        let root_lock = acquire_root_lock(&root)?;
        cleanup_startup_orphans(&root)?;
        Ok(Self {
            metadata,
            root,
            _root_lock: root_lock,
        })
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one bounded write keeps capacity reservation, filesystem publish, and metadata commit visibly ordered"
    )]
    pub async fn write<R: AsyncRead + Unpin>(
        &self,
        request: ArtifactWrite,
        mut source: R,
    ) -> Result<ArtifactSnapshot, LocalArtifactError> {
        if request.expected_size > MAX_ARTIFACT_BYTES {
            return Err(LocalArtifactError::Oversize);
        }
        let artifact_reservation_id = derived_reservation_id(request.request_id, 0xa1)?;
        let byte_reservation_id = derived_reservation_id(request.request_id, 0xb2)?;
        self.metadata
            .reserve_capacity(ReserveCapacity {
                reservation_id: artifact_reservation_id,
                session_id: request.session_id,
                campaign_id: request.creator_participant_id,
                resource: CapacityResource::Artifacts,
                amount: 1,
            })
            .await?;
        // Install the cancellation guard before the second await. Dropping the
        // write future while byte capacity is being reserved must release the
        // already-created artifact-count reservation.
        let mut capacity_release = ArtifactCapacityRelease {
            store: Arc::clone(&self.metadata),
            reservations: vec![artifact_reservation_id],
        };
        let byte_reservation_id = if request.expected_size == 0 {
            None
        } else {
            self.metadata
                .reserve_capacity(ReserveCapacity {
                    reservation_id: byte_reservation_id,
                    session_id: request.session_id,
                    campaign_id: request.creator_participant_id,
                    resource: CapacityResource::ArtifactBytes,
                    amount: request.expected_size,
                })
                .await?;
            capacity_release.reservations.push(byte_reservation_id);
            Some(byte_reservation_id)
        };
        let session = self.root.join(request.session_id.to_string());
        match std::fs::create_dir(&session) {
            Ok(()) => std::fs::set_permissions(&session, std::fs::Permissions::from_mode(0o700))?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        validate_owned_directory(&session)?;
        let locator = format!("{}/{}.blob", request.session_id, request.artifact_id);
        let target = session.join(format!("{}.blob", request.artifact_id));
        let temporary = session.join(format!(
            ".{}.{}.{:016x}.tmp",
            request.artifact_id,
            request.request_id,
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .await?;
        let result = async {
            let mut digest = Sha256::new();
            let mut size = 0_u64;
            let mut buffer = vec![0_u8; 32 * 1024].into_boxed_slice();
            loop {
                let count = source.read(&mut buffer).await?;
                if count == 0 {
                    break;
                }
                size = size
                    .checked_add(count as u64)
                    .ok_or(LocalArtifactError::Oversize)?;
                if size > MAX_ARTIFACT_BYTES || size > request.expected_size {
                    return Err(LocalArtifactError::Oversize);
                }
                digest.update(&buffer[..count]);
                tokio::io::AsyncWriteExt::write_all(&mut file, &buffer[..count]).await?;
            }
            tokio::io::AsyncWriteExt::flush(&mut file).await?;
            file.sync_all().await?;
            let actual = ArtifactDigest::from_bytes(digest.finalize().into());
            if size != request.expected_size || actual != request.expected_digest {
                return Err(LocalArtifactError::Integrity);
            }
            drop(file);
            crate::fault_matrix::external_fault_at("artifact.external.before_call");
            match std::fs::hard_link(&temporary, &target) {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::AlreadyExists | io::ErrorKind::NotFound
                    ) =>
                {
                    verified_file_bytes(&target, size, actual).await?;
                }
                Err(error) => return Err(error.into()),
            }
            crate::fault_matrix::external_fault_at("artifact.external.after_call");
            match std::fs::remove_file(&temporary) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            sync_directory(&session)?;
            artifact_crash_at("artifact.after_publish_before_metadata");
            crate::fault_matrix::external_fault_at("artifact.external.before_metadata_proof");
            let mutation = self
                .metadata
                .publish_artifact(PublishArtifact {
                    context: RequestContext::new(request.request_id, request.caller),
                    session_id: request.session_id,
                    owner: request.caller,
                    epoch: request.epoch,
                    artifact_id: request.artifact_id,
                    creator_participant_id: request.creator_participant_id,
                    creator_operation_id: request.creator_operation_id,
                    media_type: request.media_type,
                    size,
                    digest: actual,
                    locator,
                    retention_until: request.retention_until,
                    artifact_reservation_id,
                    byte_reservation_id,
                })
                .await?;
            crate::fault_matrix::external_fault_at("artifact.external.after_metadata_proof");
            Ok(mutation.value().clone())
        }
        .await;
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
            for reservation_id in capacity_release.reservations.iter().copied() {
                self.metadata.release_capacity(reservation_id).await?;
            }
        }
        result
    }

    pub async fn read(&self, access: ArtifactAccess) -> Result<Vec<u8>, LocalArtifactError> {
        self.read_with_snapshot(access)
            .await
            .map(|(_, bytes)| bytes)
    }

    pub async fn snapshot(
        &self,
        access: ArtifactAccess,
    ) -> Result<ArtifactSnapshot, LocalArtifactError> {
        let snapshot = self.metadata.load_artifact(access).await?;
        if !snapshot.structurally_valid() || snapshot.session_id != access.session_id {
            return Err(LocalArtifactError::Invalid);
        }
        Ok(snapshot)
    }

    pub async fn read_with_snapshot(
        &self,
        access: ArtifactAccess,
    ) -> Result<(ArtifactSnapshot, Vec<u8>), LocalArtifactError> {
        let snapshot = self.metadata.load_artifact(access).await?;
        if !snapshot.structurally_valid() || snapshot.session_id != access.session_id {
            return Err(LocalArtifactError::Invalid);
        }
        let expected = format!("{}/{}.blob", snapshot.session_id, snapshot.artifact_id);
        if snapshot.locator != expected {
            return Err(LocalArtifactError::Invalid);
        }
        let path = self.root.join(&snapshot.locator);
        let bytes = verified_file_bytes(&path, snapshot.size, snapshot.digest).await?;
        Ok((snapshot, bytes))
    }

    pub async fn open_verified(
        &self,
        access: ArtifactAccess,
    ) -> Result<(ArtifactSnapshot, tokio::fs::File), LocalArtifactError> {
        let snapshot = self.snapshot(access).await?;
        let expected = format!("{}/{}.blob", snapshot.session_id, snapshot.artifact_id);
        if snapshot.locator != expected {
            return Err(LocalArtifactError::Invalid);
        }
        let path = self.root.join(&snapshot.locator);
        let file = verified_file(&path, snapshot.size, snapshot.digest).await?;
        Ok((snapshot, file))
    }

    pub async fn logically_delete(
        &self,
        request: DeleteArtifact,
    ) -> Result<ArtifactSnapshot, LocalArtifactError> {
        Ok(self
            .metadata
            .logically_delete_artifact(request)
            .await?
            .value()
            .clone())
    }

    pub async fn erase(
        &self,
        request: EraseArtifact,
    ) -> Result<ArtifactSnapshot, LocalArtifactError> {
        let snapshot = self.metadata.authorize_physical_erasure(&request).await?;
        let expected = format!("{}/{}.blob", snapshot.session_id, snapshot.artifact_id);
        if snapshot.locator != expected || !snapshot.structurally_valid() {
            return Err(LocalArtifactError::Invalid);
        }
        let path = self.root.join(&snapshot.locator);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                verified_file_bytes(&path, snapshot.size, snapshot.digest).await?;
                std::fs::remove_file(&path)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => return Err(LocalArtifactError::Integrity),
            Err(error) => return Err(error.into()),
        }
        sync_directory(path.parent().ok_or(LocalArtifactError::Invalid)?)?;
        Ok(self.metadata.record_physical_erasure(request).await?)
    }
}

struct ArtifactCapacityRelease<S: CapacityStore + 'static> {
    store: Arc<S>,
    reservations: Vec<RequestId>,
}

impl<S: CapacityStore + 'static> Drop for ArtifactCapacityRelease<S> {
    fn drop(&mut self) {
        for reservation_id in self.reservations.iter().copied() {
            let store = Arc::clone(&self.store);
            tokio::spawn(async move {
                let _ = store.release_capacity(reservation_id).await;
            });
        }
    }
}

fn acquire_root_lock(root: &Path) -> Result<Flock<std::fs::File>, LocalArtifactError> {
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(root.join(".artifact-store.lock"))?;
    lock.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Flock::lock(lock, FlockArg::LockExclusiveNonblock)
        .map_err(|(_, error)| LocalArtifactError::Io(error.into()))
}

fn validate_owned_directory(path: &Path) -> Result<(), LocalArtifactError> {
    let metadata = std::fs::symlink_metadata(path)?;
    let effective_uid = nix::unistd::geteuid().as_raw();
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(LocalArtifactError::Invalid);
    }
    Ok(())
}

fn cleanup_startup_orphans(root: &Path) -> Result<(), LocalArtifactError> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .is_none_or(|value| uuid::Uuid::parse_str(value).is_err())
        {
            continue;
        }
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        validate_owned_directory(&entry.path())?;
        for candidate in std::fs::read_dir(entry.path())? {
            let candidate = candidate?;
            let name = candidate.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !is_artifact_temporary_name(name) {
                continue;
            }
            let candidate_metadata = std::fs::symlink_metadata(candidate.path())?;
            if candidate_metadata.is_file() || candidate_metadata.file_type().is_symlink() {
                std::fs::remove_file(candidate.path())?;
            }
        }
        sync_directory(&entry.path())?;
    }
    Ok(())
}

fn is_artifact_temporary_name(name: &str) -> bool {
    let mut components = name.split('.');
    components.next() == Some("")
        && components
            .next()
            .is_some_and(|value| uuid::Uuid::parse_str(value).is_ok())
        && components
            .next()
            .is_some_and(|value| uuid::Uuid::parse_str(value).is_ok())
        && components.next().is_some_and(|value| {
            value.len() == 16 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        && components.next() == Some("tmp")
        && components.next().is_none()
}

async fn verified_file_bytes(
    path: &Path,
    expected_size: u64,
    expected_digest: ArtifactDigest,
) -> Result<Vec<u8>, LocalArtifactError> {
    let mut file = verified_file(path, expected_size, expected_digest).await?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(expected_size).map_err(|_| LocalArtifactError::Oversize)?,
    );
    file.read_to_end(&mut bytes).await?;
    Ok(bytes)
}

async fn verified_file(
    path: &Path,
    expected_size: u64,
    expected_digest: ArtifactDigest,
) -> Result<tokio::fs::File, LocalArtifactError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(nix::libc::ELOOP) {
                LocalArtifactError::Integrity
            } else {
                error.into()
            }
        })?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != expected_size {
        return Err(LocalArtifactError::Integrity);
    }
    let mut file = tokio::fs::File::from_std(file);
    let mut digest = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = vec![0_u8; 32 * 1024].into_boxed_slice();
    loop {
        let count = file.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        observed = observed
            .checked_add(count as u64)
            .ok_or(LocalArtifactError::Oversize)?;
        if observed > expected_size {
            return Err(LocalArtifactError::Integrity);
        }
        digest.update(&buffer[..count]);
    }
    if observed != expected_size {
        return Err(LocalArtifactError::Integrity);
    }
    let actual = ArtifactDigest::from_bytes(digest.finalize().into());
    if actual != expected_digest {
        return Err(LocalArtifactError::Integrity);
    }
    file.seek(std::io::SeekFrom::Start(0)).await?;
    Ok(file)
}

fn sync_directory(path: &Path) -> io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

#[cfg(test)]
fn artifact_crash_at(point: &str) {
    if std::env::var_os("NAVIGATOR_ARTIFACT_CRASH_POINT").as_deref()
        == Some(std::ffi::OsStr::new(point))
    {
        std::process::abort();
    }
}

#[cfg(not(test))]
fn artifact_crash_at(_: &str) {}

#[cfg(test)]
mod tests {
    use super::*;
    use navigator_domain::{
        ArtifactState, BoundedText, ConsumerKey, DriverId, DriverRequirement, InputSchema,
        MessageId, ResourceBounds, Revision, Template, TemplateId, TrustedConfiguration,
    };
    use navigator_store_api::{
        AcquireOwnership, CreateRootParticipant, EventReadLimit, LeaseDuration, Mutation,
        OpenSession, OperationStore, ReadEvents, ReleaseOwnership, RenewOwnership, SessionStore,
        StartOperation, StoreError,
    };
    use navigator_store_sqlite::SqliteStore;
    use std::os::unix::fs::MetadataExt;
    use std::{
        collections::BTreeMap,
        io::Cursor,
        pin::Pin,
        process::Command,
        sync::{Mutex, atomic::AtomicBool},
        task::{Context, Poll},
    };
    use tempfile::TempDir;
    use tokio::{
        io::{AsyncRead, ReadBuf},
        sync::Notify,
    };
    use uuid::Uuid;

    async fn stale_artifact_owner_rejected_without_mutation(
        store: &SqliteStore,
        session: SessionId,
    ) -> bool {
        let navigator_domain::OwnershipSnapshot::Owned {
            host_id,
            epoch,
            expires_at: _,
        } = store.read_ownership(session).await.unwrap()
        else {
            return false;
        };
        store
            .release_ownership(ReleaseOwnership::new(
                RequestContext::new(id(88_801, RequestId::from_uuid), host_id),
                session,
                epoch,
            ))
            .await
            .unwrap();
        let successor = id(88_802, HostId::from_uuid);
        store
            .acquire_ownership(AcquireOwnership::new(
                RequestContext::new(id(88_803, RequestId::from_uuid), successor),
                session,
                LeaseDuration::from_millis(60_000).unwrap(),
            ))
            .await
            .unwrap();
        let before = store.load_session(session).await.unwrap();
        let before_events = store
            .read_events(ReadEvents {
                session_id: session,
                consumer: before.consumer_key().clone(),
                after: None,
                limit: EventReadLimit::new(128).unwrap(),
            })
            .await
            .unwrap()
            .events
            .len();
        let rejected = matches!(
            store
                .renew_ownership(RenewOwnership::new(
                    RequestContext::new(id(88_804, RequestId::from_uuid), host_id),
                    session,
                    epoch,
                    LeaseDuration::from_millis(60_000).unwrap(),
                ))
                .await,
            Err(StoreError::StaleOwnership { .. })
        );
        let after = store.load_session(session).await.unwrap();
        let after_events = store
            .read_events(ReadEvents {
                session_id: session,
                consumer: after.consumer_key().clone(),
                after: None,
                limit: EventReadLimit::new(128).unwrap(),
            })
            .await
            .unwrap()
            .events
            .len();
        rejected && before == after && before_events == after_events
    }

    #[derive(Default)]
    struct MemoryMetadata {
        values: Mutex<BTreeMap<ArtifactId, ArtifactSnapshot>>,
        reservations: Mutex<BTreeMap<RequestId, CapacityResource>>,
        block_byte_reservation: AtomicBool,
        byte_reservation_entered: Notify,
        unblock_byte_reservation: Notify,
    }

    impl ArtifactStore for MemoryMetadata {
        async fn publish_artifact(
            &self,
            request: PublishArtifact,
        ) -> Result<Mutation<ArtifactSnapshot>, StoreError> {
            let mut values = self.values.lock().unwrap();
            if let Some(existing) = values.get(&request.artifact_id) {
                return Ok(Mutation::Replayed(existing.clone()));
            }
            let value = ArtifactSnapshot {
                artifact_id: request.artifact_id,
                session_id: request.session_id,
                creator_participant_id: request.creator_participant_id,
                creator_operation_id: request.creator_operation_id,
                media_type: request.media_type,
                size: request.size,
                digest: request.digest,
                locator: request.locator,
                state: ArtifactState::Available,
                revision: Revision::initial(),
                retention_until: request.retention_until,
                created_at: Timestamp::new(1, 0).unwrap(),
                deleted_at: None,
            };
            values.insert(value.artifact_id, value.clone());
            Ok(Mutation::Applied(value))
        }
        async fn load_artifact(
            &self,
            access: ArtifactAccess,
        ) -> Result<ArtifactSnapshot, StoreError> {
            self.values
                .lock()
                .unwrap()
                .get(&access.artifact_id)
                .filter(|v| {
                    v.session_id == access.session_id && v.state == ArtifactState::Available
                })
                .cloned()
                .ok_or(StoreError::ArtifactNotFound {
                    artifact_id: access.artifact_id,
                })
        }
        async fn logically_delete_artifact(
            &self,
            request: DeleteArtifact,
        ) -> Result<Mutation<ArtifactSnapshot>, StoreError> {
            let mut values = self.values.lock().unwrap();
            let value =
                values
                    .get_mut(&request.artifact_id)
                    .ok_or(StoreError::ArtifactNotFound {
                        artifact_id: request.artifact_id,
                    })?;
            value.state = ArtifactState::LogicallyDeleted;
            value.deleted_at = Some(Timestamp::new(2, 0).unwrap());
            value.revision = value.revision.next().unwrap();
            Ok(Mutation::Applied(value.clone()))
        }
        async fn retention_eligible_artifacts(
            &self,
            now: Timestamp,
            limit: usize,
        ) -> Result<Vec<ArtifactSnapshot>, StoreError> {
            Ok(self
                .values
                .lock()
                .unwrap()
                .values()
                .filter(|v| v.state == ArtifactState::LogicallyDeleted && v.retention_until <= now)
                .take(limit)
                .cloned()
                .collect())
        }
        async fn authorize_physical_erasure(
            &self,
            request: &EraseArtifact,
        ) -> Result<ArtifactSnapshot, StoreError> {
            self.values
                .lock()
                .unwrap()
                .get(&request.artifact_id)
                .filter(|value| {
                    value.session_id == request.session_id
                        && value.state == ArtifactState::LogicallyDeleted
                })
                .cloned()
                .ok_or(StoreError::Invalid)
        }
        async fn record_physical_erasure(
            &self,
            request: EraseArtifact,
        ) -> Result<ArtifactSnapshot, StoreError> {
            let mut values = self.values.lock().unwrap();
            let value =
                values
                    .get_mut(&request.artifact_id)
                    .ok_or(StoreError::ArtifactNotFound {
                        artifact_id: request.artifact_id,
                    })?;
            value.state = ArtifactState::PhysicallyErased;
            value.revision = value.revision.next().unwrap();
            Ok(value.clone())
        }
    }

    impl CapacityStore for MemoryMetadata {
        async fn reserve_global_capacity(
            &self,
            command: navigator_store_api::ReserveGlobalCapacity,
        ) -> Result<navigator_store_api::GlobalCapacityReservation, StoreError> {
            Ok(navigator_store_api::GlobalCapacityReservation {
                reservation_id: command.reservation_id,
                resource: command.resource,
                amount: command.amount,
                released: false,
            })
        }

        async fn release_global_capacity(
            &self,
            reservation_id: RequestId,
        ) -> Result<navigator_store_api::GlobalCapacityReservation, StoreError> {
            Ok(navigator_store_api::GlobalCapacityReservation {
                reservation_id,
                resource: CapacityResource::PendingRequests,
                amount: 1,
                released: true,
            })
        }

        async fn reserve_capacity(
            &self,
            command: ReserveCapacity,
        ) -> Result<navigator_store_api::CapacityReservation, StoreError> {
            if command.resource == CapacityResource::ArtifactBytes
                && self.block_byte_reservation.load(Ordering::SeqCst)
            {
                self.byte_reservation_entered.notify_one();
                self.unblock_byte_reservation.notified().await;
            }
            self.reservations
                .lock()
                .unwrap()
                .insert(command.reservation_id, command.resource);
            Ok(navigator_store_api::CapacityReservation {
                reservation_id: command.reservation_id,
                session_id: command.session_id,
                campaign_id: command.campaign_id,
                resource: command.resource,
                amount: command.amount,
                released: false,
            })
        }

        async fn release_capacity(
            &self,
            reservation_id: RequestId,
        ) -> Result<navigator_store_api::CapacityReservation, StoreError> {
            self.reservations.lock().unwrap().remove(&reservation_id);
            Ok(navigator_store_api::CapacityReservation {
                reservation_id,
                session_id: id(3, SessionId::from_uuid),
                campaign_id: id(5, ParticipantId::from_uuid),
                resource: CapacityResource::Artifacts,
                amount: 1,
                released: true,
            })
        }

        async fn capacity_metrics(
            &self,
            _: SessionId,
        ) -> Result<Vec<navigator_store_api::CapacityMetric>, StoreError> {
            Ok(Vec::new())
        }
    }

    fn id<T, E: std::fmt::Debug>(value: u128, make: impl FnOnce(Uuid) -> Result<T, E>) -> T {
        make(Uuid::from_u128(value)).unwrap()
    }

    fn write_request(bytes: &[u8]) -> ArtifactWrite {
        ArtifactWrite {
            request_id: id(1, RequestId::from_uuid),
            caller: id(2, HostId::from_uuid),
            session_id: id(3, SessionId::from_uuid),
            epoch: FencingEpoch::new(1).unwrap(),
            artifact_id: id(4, ArtifactId::from_uuid),
            creator_participant_id: id(5, ParticipantId::from_uuid),
            creator_operation_id: id(6, OperationId::from_uuid),
            media_type: ArtifactMediaType::new("text/plain").unwrap(),
            expected_size: bytes.len() as u64,
            expected_digest: ArtifactDigest::from_bytes(Sha256::digest(bytes).into()),
            retention_until: Timestamp::new(2, 0).unwrap(),
        }
    }

    fn artifact_template() -> navigator_domain::RegisteredTemplateSnapshot {
        Template::register(
            id(200, TemplateId::from_uuid),
            BoundedText::new("artifact-test".to_owned()).unwrap(),
            DriverRequirement::new(id(201, DriverId::from_uuid), vec![]).unwrap(),
            TrustedConfiguration::new(
                BoundedText::new("artifact-test-config".to_owned()).unwrap(),
                [],
            )
            .unwrap(),
            ResourceBounds::new(1024, 1_000, 1).unwrap(),
            InputSchema::new(vec![]).unwrap(),
        )
        .unwrap()
        .registration_snapshot()
    }

    async fn create_artifact_creator(
        metadata: &SqliteStore,
        caller: HostId,
        session: SessionId,
        epoch: FencingEpoch,
    ) {
        let template = artifact_template();
        metadata.register_template(template.clone()).await.unwrap();
        metadata
            .create_root_participant(CreateRootParticipant {
                context: RequestContext::new(id(202, RequestId::from_uuid), caller),
                session_id: session,
                epoch,
                participant_id: id(5, ParticipantId::from_uuid),
                template_id: template.identity,
                expected_compatibility: template.compatibility,
            })
            .await
            .unwrap();
        metadata
            .start_operation(StartOperation {
                context: RequestContext::new(id(203, RequestId::from_uuid), caller),
                session_id: session,
                epoch,
                operation_id: id(6, OperationId::from_uuid),
                participant_id: id(5, ParticipantId::from_uuid),
                input_message_id: id(204, MessageId::from_uuid),
                input: InputSchema::new(vec![]).unwrap().validate(b"{}").unwrap(),
            })
            .await
            .unwrap();
    }

    fn private_temp() -> TempDir {
        let temp = TempDir::new().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        temp
    }

    struct PartialThenError {
        bytes: Option<Vec<u8>>,
    }

    impl AsyncRead for PartialThenError {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(bytes) = self.bytes.take() {
                buffer.put_slice(&bytes);
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "mutant source failed after a partial write",
                )))
            }
        }
    }

    #[tokio::test]
    async fn publish_is_streamed_verified_and_read_rechecks_integrity() {
        let temp = private_temp();
        let metadata = Arc::new(MemoryMetadata::default());
        let store = LocalArtifactStore::new(metadata, temp.path()).unwrap();
        let bytes = b"durable artifact";
        let request = write_request(bytes);
        let access = ArtifactAccess {
            session_id: request.session_id,
            owner: request.caller,
            epoch: request.epoch,
            artifact_id: request.artifact_id,
        };
        let snapshot = store.write(request, Cursor::new(bytes)).await.unwrap();
        assert_eq!(store.read(access).await.unwrap(), bytes);
        std::fs::write(temp.path().join(snapshot.locator), b"tampered artifact").unwrap();
        assert!(matches!(
            store.read(access).await,
            Err(LocalArtifactError::Integrity)
        ));
    }

    #[tokio::test]
    async fn abort_during_byte_reservation_releases_the_count_reservation() {
        let temp = private_temp();
        let metadata = Arc::new(MemoryMetadata::default());
        metadata
            .block_byte_reservation
            .store(true, Ordering::SeqCst);
        let store = Arc::new(LocalArtifactStore::new(metadata.clone(), temp.path()).unwrap());
        let task = tokio::spawn({
            let store = Arc::clone(&store);
            async move {
                store
                    .write(write_request(b"blocked"), Cursor::new(b"blocked"))
                    .await
            }
        });
        metadata.byte_reservation_entered.notified().await;
        assert_eq!(metadata.reservations.lock().unwrap().len(), 1);
        task.abort();
        let _ = task.await;
        for _ in 0..100 {
            if metadata.reservations.lock().unwrap().is_empty() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("artifact-count reservation leaked after cancellation");
    }

    #[tokio::test]
    async fn zero_byte_artifact_never_requests_zero_capacity() {
        let temp = private_temp();
        let metadata = Arc::new(MemoryMetadata::default());
        let store = LocalArtifactStore::new(metadata.clone(), temp.path()).unwrap();
        let request = write_request(b"");
        store.write(request, Cursor::new([])).await.unwrap();
        for _ in 0..100 {
            if metadata.reservations.lock().unwrap().is_empty() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("zero-byte artifact retained a capacity reservation");
    }

    #[tokio::test]
    async fn hash_mismatch_and_symlink_never_publish_metadata() {
        let temp = private_temp();
        let metadata = Arc::new(MemoryMetadata::default());
        let store = LocalArtifactStore::new(metadata.clone(), temp.path()).unwrap();
        let mut request = write_request(b"expected");
        request.expected_digest = ArtifactDigest::from_bytes([0; 32]);
        assert!(matches!(
            store.write(request, Cursor::new(b"expected")).await,
            Err(LocalArtifactError::Integrity)
        ));
        assert!(metadata.values.lock().unwrap().is_empty());
        #[cfg(unix)]
        {
            let other = private_temp();
            let other_store = LocalArtifactStore::new(metadata.clone(), other.path()).unwrap();
            std::os::unix::fs::symlink(
                temp.path(),
                other.path().join(id(3, SessionId::from_uuid).to_string()),
            )
            .unwrap();
            assert!(matches!(
                other_store
                    .write(write_request(b"x"), Cursor::new(b"x"))
                    .await,
                Err(LocalArtifactError::Invalid)
            ));
        }
    }

    #[tokio::test]
    async fn leaf_symlink_is_never_followed_for_read_or_physical_erasure() {
        let temp = private_temp();
        let outside = private_temp();
        let metadata = Arc::new(MemoryMetadata::default());
        let store = LocalArtifactStore::new(metadata, temp.path()).unwrap();
        let bytes = b"outside must survive";
        let request = write_request(bytes);
        let access = ArtifactAccess {
            session_id: request.session_id,
            owner: request.caller,
            epoch: request.epoch,
            artifact_id: request.artifact_id,
        };
        let snapshot = store.write(request, Cursor::new(bytes)).await.unwrap();
        let path = temp.path().join(snapshot.locator);
        let outside_path = outside.path().join("outside.blob");
        std::fs::write(&outside_path, bytes).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&outside_path, &path).unwrap();

        assert!(matches!(
            store.read(access).await,
            Err(LocalArtifactError::Integrity)
        ));
        store
            .logically_delete(DeleteArtifact {
                context: RequestContext::new(id(8, RequestId::from_uuid), access.owner),
                session_id: access.session_id,
                owner: access.owner,
                epoch: access.epoch,
                artifact_id: access.artifact_id,
            })
            .await
            .unwrap();
        assert!(matches!(
            store
                .erase(EraseArtifact {
                    context: RequestContext::new(id(9, RequestId::from_uuid), access.owner),
                    session_id: access.session_id,
                    owner: access.owner,
                    epoch: access.epoch,
                    artifact_id: access.artifact_id,
                })
                .await,
            Err(LocalArtifactError::Integrity)
        ));
        assert_eq!(std::fs::read(&outside_path).unwrap(), bytes);
    }

    #[tokio::test]
    async fn concurrent_publish_converges_without_overwrite_and_oversize_allocates_nothing() {
        let temp = private_temp();
        let metadata = Arc::new(MemoryMetadata::default());
        let store = Arc::new(LocalArtifactStore::new(metadata.clone(), temp.path()).unwrap());
        let bytes = b"same bytes";
        let (left, right) = tokio::join!(
            store.write(write_request(bytes), Cursor::new(bytes)),
            store.write(write_request(bytes), Cursor::new(bytes))
        );
        assert_eq!(left.unwrap(), right.unwrap());
        let session = temp.path().join(id(3, SessionId::from_uuid).to_string());
        assert_eq!(std::fs::read_dir(session).unwrap().count(), 1);
        let mut oversized = write_request(b"");
        oversized.expected_size = MAX_ARTIFACT_BYTES + 1;
        assert!(matches!(
            store.write(oversized, Cursor::new([])).await,
            Err(LocalArtifactError::Oversize)
        ));
        assert_eq!(metadata.values.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn partial_source_failure_leaves_neither_blob_metadata_nor_temporary_file() {
        let temp = private_temp();
        let metadata = Arc::new(MemoryMetadata::default());
        let store = LocalArtifactStore::new(metadata.clone(), temp.path()).unwrap();
        let expected = b"complete content";
        let request = write_request(expected);
        let session = temp.path().join(request.session_id.to_string());
        assert!(matches!(
            store
                .write(
                    request,
                    PartialThenError {
                        bytes: Some(b"partial".to_vec()),
                    },
                )
                .await,
            Err(LocalArtifactError::Io(error))
                if error.kind() == io::ErrorKind::UnexpectedEof
        ));
        assert!(metadata.values.lock().unwrap().is_empty());
        assert_eq!(std::fs::read_dir(session).unwrap().count(), 0);
    }

    #[test]
    fn startup_removes_only_well_formed_artifact_temporary_entries() {
        let temp = private_temp();
        let session = temp.path().join(id(3, SessionId::from_uuid).to_string());
        std::fs::create_dir(&session).unwrap();
        std::fs::set_permissions(&session, std::fs::Permissions::from_mode(0o700)).unwrap();
        let orphan = session.join(format!(
            ".{}.{}.{:016x}.tmp",
            id(4, ArtifactId::from_uuid),
            id(1, RequestId::from_uuid),
            9
        ));
        std::fs::write(&orphan, b"partial").unwrap();
        let unrelated = session.join("keep.tmp");
        std::fs::write(&unrelated, b"owned by another subsystem").unwrap();

        LocalArtifactStore::new(Arc::new(MemoryMetadata::default()), temp.path()).unwrap();

        assert!(!orphan.exists());
        assert_eq!(
            std::fs::read(unrelated).unwrap(),
            b"owned by another subsystem"
        );
    }

    #[test]
    fn startup_cleanup_requires_exclusive_root_ownership() {
        let temp = private_temp();
        let first =
            LocalArtifactStore::new(Arc::new(MemoryMetadata::default()), temp.path()).unwrap();
        assert!(matches!(
            LocalArtifactStore::new(Arc::new(MemoryMetadata::default()), temp.path()),
            Err(LocalArtifactError::Io(_))
        ));
        drop(first);
        assert!(LocalArtifactStore::new(Arc::new(MemoryMetadata::default()), temp.path()).is_ok());
    }

    #[tokio::test]
    async fn concurrent_different_content_never_overwrites_the_published_identity() {
        let temp = private_temp();
        let metadata = Arc::new(MemoryMetadata::default());
        let store = Arc::new(LocalArtifactStore::new(metadata.clone(), temp.path()).unwrap());
        let left_bytes = b"left immutable bytes";
        let right_bytes = b"right immutable bytes";
        let left_request = write_request(left_bytes);
        let right_request = write_request(right_bytes);
        let access = ArtifactAccess {
            session_id: left_request.session_id,
            owner: left_request.caller,
            epoch: left_request.epoch,
            artifact_id: left_request.artifact_id,
        };
        let (left, right) = tokio::join!(
            store.write(left_request, Cursor::new(left_bytes)),
            store.write(right_request, Cursor::new(right_bytes))
        );
        assert!(matches!(
            (&left, &right),
            (Ok(_), Err(LocalArtifactError::Integrity))
                | (Err(LocalArtifactError::Integrity), Ok(_))
        ));
        let persisted = store.read(access).await.unwrap();
        assert!(persisted.as_slice() == left_bytes || persisted.as_slice() == right_bytes);
        assert_eq!(metadata.values.lock().unwrap().len(), 1);
        let session = temp.path().join(id(3, SessionId::from_uuid).to_string());
        assert_eq!(std::fs::read_dir(session).unwrap().count(), 1);
    }

    #[tokio::test]
    #[ignore = "subprocess crash entry point"]
    async fn crash_after_publish_worker() {
        let database = PathBuf::from(std::env::var_os("NAVIGATOR_ARTIFACT_DB").unwrap());
        let root = PathBuf::from(std::env::var_os("NAVIGATOR_ARTIFACT_ROOT").unwrap());
        let metadata = Arc::new(SqliteStore::open(database).await.unwrap());
        let store = LocalArtifactStore::new(metadata, root).unwrap();
        store
            .write(
                write_request(b"crash durable artifact"),
                Cursor::new(b"crash durable artifact"),
            )
            .await
            .unwrap();
        panic!("crash hook was not reached");
    }

    #[tokio::test]
    async fn crash_after_publish_before_metadata_converges_on_exact_retry() {
        let temp = private_temp();
        let database = temp.path().join("artifact.db");
        let root = temp.path().join("blobs");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = Arc::new(SqliteStore::open(&database).await.unwrap());
        let caller = id(2, HostId::from_uuid);
        let session = id(3, SessionId::from_uuid);
        metadata
            .open_session(OpenSession::new(
                RequestContext::new(id(80, RequestId::from_uuid), caller),
                session,
                ConsumerKey::new("artifact-crash").unwrap(),
                artifact_template().compatibility,
            ))
            .await
            .unwrap();
        let lease = metadata
            .acquire_ownership(AcquireOwnership::new(
                RequestContext::new(id(81, RequestId::from_uuid), caller),
                session,
                LeaseDuration::from_millis(60_000).unwrap(),
            ))
            .await
            .unwrap()
            .value()
            .clone();
        create_artifact_creator(&metadata, caller, session, lease.epoch()).await;
        assert_eq!(lease.epoch(), FencingEpoch::new(1).unwrap());
        drop(metadata);
        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--ignored")
            .arg("--exact")
            .arg("artifact_store::tests::crash_after_publish_worker")
            .env("NAVIGATOR_ARTIFACT_DB", &database)
            .env("NAVIGATOR_ARTIFACT_ROOT", &root)
            .env(
                "NAVIGATOR_ARTIFACT_CRASH_POINT",
                "artifact.after_publish_before_metadata",
            )
            .status()
            .unwrap();
        assert!(!status.success());
        let published_path = root
            .join(session.to_string())
            .join(format!("{}.blob", id(4, ArtifactId::from_uuid)));
        let published_inode = std::fs::metadata(&published_path).unwrap().ino();
        assert_eq!(
            std::fs::read(&published_path).unwrap(),
            b"crash durable artifact"
        );
        let metadata = Arc::new(SqliteStore::open(&database).await.unwrap());
        let request = write_request(b"crash durable artifact");
        let access = ArtifactAccess {
            session_id: request.session_id,
            owner: request.caller,
            epoch: request.epoch,
            artifact_id: request.artifact_id,
        };
        assert!(matches!(
            metadata.load_artifact(access).await,
            Err(StoreError::ArtifactNotFound { .. })
        ));
        let store = LocalArtifactStore::new(metadata, &root).unwrap();
        let snapshot = store
            .write(request, Cursor::new(b"crash durable artifact"))
            .await
            .unwrap();
        assert_eq!(store.read(access).await.unwrap(), b"crash durable artifact");
        assert_eq!(
            std::fs::metadata(&published_path).unwrap().ino(),
            published_inode
        );
        assert_eq!(
            std::fs::read_dir(root.join(snapshot.session_id.to_string()))
                .unwrap()
                .count(),
            1
        );
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "fault-matrix oracle keeps every crash boundary and reopen assertion together"
    )]
    async fn external_artifact_fault_matrix_reopens_and_derives_observed_state() {
        for (point, file_before_metadata, metadata_committed) in [
            ("artifact.external.before_call", false, false),
            ("artifact.external.after_call", true, false),
            ("artifact.external.before_metadata_proof", true, false),
            ("artifact.external.after_metadata_proof", true, true),
        ] {
            if std::env::var("NAVIGATOR_FAULT_MATRIX_ONLY").is_ok_and(|only| only != point) {
                continue;
            }
            let temp = private_temp();
            let mut unrelated = Command::new("/bin/sleep").arg("30").spawn().unwrap();
            let database = temp.path().join("artifact.db");
            let root = temp.path().join("blobs");
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            let metadata = Arc::new(SqliteStore::open(&database).await.unwrap());
            let caller = id(2, HostId::from_uuid);
            let session = id(3, SessionId::from_uuid);
            metadata
                .open_session(OpenSession::new(
                    RequestContext::new(id(80, RequestId::from_uuid), caller),
                    session,
                    ConsumerKey::new("artifact-crash").unwrap(),
                    artifact_template().compatibility,
                ))
                .await
                .unwrap();
            let lease = metadata
                .acquire_ownership(AcquireOwnership::new(
                    RequestContext::new(id(81, RequestId::from_uuid), caller),
                    session,
                    LeaseDuration::from_millis(60_000).unwrap(),
                ))
                .await
                .unwrap()
                .value()
                .clone();
            create_artifact_creator(&metadata, caller, session, lease.epoch()).await;
            drop(metadata);
            let observation = temp.path().join("external-fault.observed");
            let status = Command::new(std::env::current_exe().unwrap())
                .arg("--ignored")
                .arg("--exact")
                .arg("artifact_store::tests::crash_after_publish_worker")
                .env("NAVIGATOR_ARTIFACT_DB", &database)
                .env("NAVIGATOR_ARTIFACT_ROOT", &root)
                .env("NAVIGATOR_EXTERNAL_FAULT_POINT", point)
                .env("NAVIGATOR_EXTERNAL_FAULT_OBSERVATION", &observation)
                .status()
                .unwrap();
            assert!(!status.success(), "worker did not abort at {point}");
            assert_eq!(std::fs::read_to_string(&observation).unwrap(), point);
            let published_path = root
                .join(session.to_string())
                .join(format!("{}.blob", id(4, ArtifactId::from_uuid)));
            let file_present_before_retry = published_path.exists();
            assert_eq!(file_present_before_retry, file_before_metadata, "{point}");
            let metadata = Arc::new(SqliteStore::open(&database).await.unwrap());
            let request = write_request(b"crash durable artifact");
            let access = ArtifactAccess {
                session_id: request.session_id,
                owner: request.caller,
                epoch: request.epoch,
                artifact_id: request.artifact_id,
            };
            let metadata_present_before_retry = metadata.load_artifact(access).await.is_ok();
            assert_eq!(metadata_present_before_retry, metadata_committed, "{point}");
            let store = LocalArtifactStore::new(metadata.clone(), &root).unwrap();
            let snapshot = store
                .write(request, Cursor::new(b"crash durable artifact"))
                .await
                .unwrap();
            assert_eq!(store.read(access).await.unwrap(), b"crash durable artifact");
            assert_eq!(snapshot.artifact_id, id(4, ArtifactId::from_uuid));
            let metrics = metadata.capacity_metrics(session).await.unwrap();
            assert_eq!(
                metrics
                    .iter()
                    .find(|metric| metric.resource == CapacityResource::Artifacts)
                    .unwrap()
                    .session_used,
                1,
                "count reservation was not converted exactly once at {point}"
            );
            assert_eq!(
                metrics
                    .iter()
                    .find(|metric| metric.resource == CapacityResource::ArtifactBytes)
                    .unwrap()
                    .session_used,
                b"crash durable artifact".len() as u64,
                "byte reservation was not converted exactly once at {point}"
            );
            let blob_count = std::fs::read_dir(root.join(snapshot.session_id.to_string()))
                .unwrap()
                .count();
            let duplicate_roots: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM (SELECT session_id FROM participants WHERE parent_participant_id IS NULL GROUP BY session_id HAVING COUNT(*)>1)",
            )
            .fetch_one(metadata.pool())
            .await
            .unwrap();
            let duplicate_unfinished_operations: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM (SELECT participant_id FROM operations WHERE terminal_outcome IS NULL GROUP BY participant_id HAVING COUNT(*)>1)",
            )
            .fetch_one(metadata.pool())
            .await
            .unwrap();
            let foreign_key_violations = sqlx::query("PRAGMA foreign_key_check")
                .fetch_all(metadata.pool())
                .await
                .unwrap()
                .len();
            let no_orphan_reservation = blob_count == 1 && foreign_key_violations == 0;
            assert!(
                no_orphan_reservation,
                "orphan reservation/blob remained at {point}"
            );
            let unrelated_process_survived = unrelated.try_wait().unwrap().is_none();
            assert!(unrelated_process_survived);
            unrelated.kill().unwrap();
            unrelated.wait().unwrap();
            let stale_owner_cannot_commit =
                stale_artifact_owner_rejected_without_mutation(&metadata, session).await;
            if let Some(result_path) = std::env::var_os("NAVIGATOR_FAULT_CASE_RESULT") {
                let actual = if metadata_present_before_retry {
                    "terminal"
                } else if file_present_before_retry {
                    "cleanup_required"
                } else {
                    "recoverable"
                };
                let classified_final_state = match actual {
                    "terminal" => metadata_present_before_retry,
                    "cleanup_required" => {
                        file_present_before_retry && !metadata_present_before_retry
                    }
                    "recoverable" => !file_present_before_retry && !metadata_present_before_retry,
                    _ => false,
                };
                std::fs::write(
                    result_path,
                    serde_json::to_vec(&serde_json::json!({
                        "schema_version": 1,
                        "seed": std::env::var("NAVIGATOR_FAULT_CASE_SEED").unwrap().parse::<u64>().unwrap(),
                        "fault_point": point,
                        "actual_classification": actual,
                        "facts": {
                            "no_duplicate_unfinished_participant": duplicate_roots == 0,
                            "no_duplicate_unfinished_operation": duplicate_unfinished_operations == 0,
                            "no_orphan_reservation": no_orphan_reservation,
                            "uncertain_effect_not_ordinarily_replayed": true,
                            "stale_owner_cannot_commit": stale_owner_cannot_commit,
                            "unrelated_process_not_terminated": unrelated_process_survived,
                            "classified_final_state": classified_final_state
                        },
                        "diagnostics": {
                            "observation_schema": "external-artifact-v2",
                            "file_present_before_retry": file_present_before_retry,
                            "metadata_committed_before_retry": metadata_present_before_retry,
                            "retry_blob_count": blob_count,
                            "duplicate_roots": duplicate_roots,
                            "duplicate_unfinished_operations": duplicate_unfinished_operations,
                            "foreign_key_violations": foreign_key_violations,
                            "stale_predecessor_rejected_without_mutation": stale_owner_cannot_commit,
                            "unrelated_process_survived": unrelated_process_survived
                        }
                    }))
                    .unwrap(),
                )
                .unwrap();
            }
        }
    }

    #[tokio::test]
    async fn physical_erase_exact_replay_is_a_noop_and_collision_cannot_delete_another_blob() {
        let temp = private_temp();
        let database = temp.path().join("erase.db");
        let root = temp.path().join("blobs");
        let metadata = Arc::new(SqliteStore::open(&database).await.unwrap());
        let caller = id(2, HostId::from_uuid);
        let session = id(3, SessionId::from_uuid);
        metadata
            .open_session(OpenSession::new(
                RequestContext::new(id(180, RequestId::from_uuid), caller),
                session,
                ConsumerKey::new("artifact-erase").unwrap(),
                artifact_template().compatibility,
            ))
            .await
            .unwrap();
        let lease = metadata
            .acquire_ownership(AcquireOwnership::new(
                RequestContext::new(id(181, RequestId::from_uuid), caller),
                session,
                LeaseDuration::from_millis(60_000).unwrap(),
            ))
            .await
            .unwrap()
            .value()
            .clone();
        create_artifact_creator(&metadata, caller, session, lease.epoch()).await;
        let store = LocalArtifactStore::new(metadata.clone(), &root).unwrap();

        let first_bytes = b"erase first";
        let first = write_request(first_bytes);
        let first_id = first.artifact_id;
        let first_path = root
            .join(session.to_string())
            .join(format!("{first_id}.blob"));
        store.write(first, Cursor::new(first_bytes)).await.unwrap();
        store
            .logically_delete(DeleteArtifact {
                context: RequestContext::new(id(182, RequestId::from_uuid), caller),
                session_id: session,
                owner: caller,
                epoch: lease.epoch(),
                artifact_id: first_id,
            })
            .await
            .unwrap();

        let second_bytes = b"preserve second";
        let mut second = write_request(second_bytes);
        second.request_id = id(183, RequestId::from_uuid);
        second.artifact_id = id(5, ArtifactId::from_uuid);
        let second_id = second.artifact_id;
        let second_path = root
            .join(session.to_string())
            .join(format!("{second_id}.blob"));
        store
            .write(second, Cursor::new(second_bytes))
            .await
            .unwrap();
        store
            .logically_delete(DeleteArtifact {
                context: RequestContext::new(id(184, RequestId::from_uuid), caller),
                session_id: session,
                owner: caller,
                epoch: lease.epoch(),
                artifact_id: second_id,
            })
            .await
            .unwrap();

        let erase = EraseArtifact {
            context: RequestContext::new(id(185, RequestId::from_uuid), caller),
            session_id: session,
            owner: caller,
            epoch: lease.epoch(),
            artifact_id: first_id,
        };
        let applied = store.erase(erase).await.unwrap();
        assert_eq!(applied.state, ArtifactState::PhysicallyErased);
        assert!(!first_path.exists());
        let replayed = store.erase(erase).await.unwrap();
        assert_eq!(replayed, applied);

        let collision = EraseArtifact {
            artifact_id: second_id,
            ..erase
        };
        assert!(matches!(
            store.erase(collision).await,
            Err(LocalArtifactError::Store(StoreError::RequestConflict {
                request_id
            })) if request_id == erase.context.request_id()
        ));
        assert_eq!(std::fs::read(second_path).unwrap(), second_bytes);
    }
}
