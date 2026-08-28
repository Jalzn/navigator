use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
};

use navigator_conformance::effect_journal::{EffectJournalFixture, assert_effect_journal_contract};
use navigator_conformance::instance_store::{InstanceStoreFixture, assert_instance_store_contract};
use navigator_conformance::mailbox_store::{
    MailboxScope, MailboxStoreFixture, assert_mailbox_store_contract,
};
use navigator_conformance::operation_store::{
    OperationStoreFixture, PRIVATE_EVENT_SENTINEL, assert_operation_store_contract,
};
use navigator_conformance::store::{SessionStoreFixture, assert_session_store_contract};
use navigator_conformance::tool_store::{ToolStoreFixture, assert_tool_store_contract};
use navigator_conformance::topology_store::{
    TopologyScope, TopologyStoreFixture, assert_topology_store_contract,
};
use navigator_domain::{
    AuthorityProfile, BoundedText, CanonicalJson, Capability, Clock, CompatibilityIdentity,
    ConsumerKey, DeliveryAttemptId, DriverId, DriverRequirement, EffectClass, FeedbackKind,
    FencingEpoch, Grant, GrantId, HostId, IdempotencyContract, InputSchema, InstanceId,
    LaunchAttemptId, MAX_TOOL_INLINE_BYTES, MAX_TOOL_SCHEMA_BYTES, MessageId, MonotonicInstant,
    OperationAction, OperationId, ParticipantId, RequestId, ResourceBounds, ResourceScope,
    Revision, ScopedCapability, SessionId, Template, TemplateId, Timestamp, ToolCancellation,
    ToolConnectionId, ToolDefinition, ToolDispatchId, ToolInvocation, ToolInvocationId, ToolName,
    ToolProviderId, ToolRegistrationId, ToolTimeout, ToolVersion, TrustedConfiguration,
};
use navigator_store_api::{
    AcquireOwnership, ApplyHierarchyEffect, AttachLaunch, AuthorityEffectOutcome,
    AuthorityPolicySnapshot, AuthorityStore, AuthorityTemplatePolicy, AuthorizedChildOutcome,
    AuthorizedStatus, AuthorizedStatusOutcome, CancelSubtree, CheckAuthorityEffect,
    ConnectToolProvider, CreateAuthorizedChild, CreateChildParticipant, CreateRootParticipant,
    DeliveryTransition, EffectJournalStore, EnqueueMessage, GrantSnapshot, HierarchyEffect,
    HierarchyEffectOutcome, HierarchyStore, InstanceStore, IssueGrant, LaunchState, LeaseDuration,
    LeaseNextMessage, MailboxStore, MessageCorrelation, MessageDeliveryState, MessageSnapshot,
    OpenSession, OperationStore, PrepareLaunch, ProcessEvidence, PutAuthorityPolicy,
    RegisterAuthorityTemplatePolicy, RegisterTool, ReleaseOwnership, RequestContext,
    ReserveToolInvocation, RevokeGrant, SessionStore, StartOperation, StoreError, ToolStore,
    TransitionLaunch, TransitionMessageDelivery, TransitionOperation,
};
use navigator_store_sqlite::SqliteStore;
use tempfile::TempDir;
use uuid::Uuid;

struct TrustedClock(AtomicI64);

impl TrustedClock {
    fn new(seconds: i64) -> Self {
        Self(AtomicI64::new(seconds))
    }

    fn set(&self, seconds: i64) {
        self.0.store(seconds, Ordering::SeqCst);
    }
}

impl Clock for TrustedClock {
    fn wall_now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::SeqCst))
            .expect("contract clock is representable")
    }

    fn monotonic_now(&self) -> MonotonicInstant {
        MonotonicInstant::from_ticks(0)
    }
}

struct SqliteFixture {
    _directory: TempDir,
    path: PathBuf,
    clock: Arc<TrustedClock>,
    store: SqliteStore,
    next_tool_request: u128,
}

impl SqliteFixture {
    async fn new() -> Self {
        let directory = TempDir::new().expect("temporary Store directory");
        let path = directory.path().join("contract.db");
        let clock = Arc::new(TrustedClock::new(100));
        let store = open(&path, clock.clone())
            .await
            .expect("open contract Store");
        Self {
            _directory: directory,
            path,
            clock,
            store,
            next_tool_request: 120_100,
        }
    }
}

impl SessionStoreFixture for SqliteFixture {
    type Store = SqliteStore;

    fn store(&self) -> &Self::Store {
        &self.store
    }

    fn set_wall_seconds(&self, seconds: i64) {
        self.clock.set(seconds);
    }

    async fn reopen(&mut self) -> Result<(), StoreError> {
        self.store.pool().close().await;
        self.store = open(&self.path, self.clock.clone()).await?;
        Ok(())
    }
}

impl EffectJournalFixture for SqliteFixture {
    type Store = SqliteStore;
    fn store(&self) -> &Self::Store {
        &self.store
    }
    fn set_wall_seconds(&self, seconds: i64) {
        self.clock.set(seconds);
    }
    async fn reopen(&mut self) -> Result<(), StoreError> {
        self.store.pool().close().await;
        self.store = open(&self.path, self.clock.clone()).await?;
        Ok(())
    }
    async fn prepare_linkage(
        &mut self,
    ) -> Result<(SessionId, HostId, ParticipantId, OperationId), String> {
        assert_operation_store_contract(self).await?;
        self.clock.set(201);
        let session = SessionId::from_uuid(Uuid::from_u128(800)).unwrap();
        let owner = HostId::from_uuid(Uuid::from_u128(801)).unwrap();
        let operation = OperationId::from_uuid(Uuid::from_u128(824)).unwrap();
        let lease = self
            .store
            .acquire_ownership(AcquireOwnership::new(
                RequestContext::new(
                    RequestId::from_uuid(Uuid::from_u128(99_001)).unwrap(),
                    owner,
                ),
                session,
                LeaseDuration::from_millis(10_000).unwrap(),
            ))
            .await
            .map_err(|e| e.to_string())?
            .value()
            .clone();
        accept_operation_message(
            &self.store,
            session,
            owner,
            lease.epoch(),
            ParticipantId::from_uuid(Uuid::from_u128(806)).unwrap(),
            MessageId::from_uuid(Uuid::from_u128(825)).unwrap(),
            99_100,
        )
        .await?;
        for (request, revision, action) in [
            (99_002, 1, OperationAction::BeginStart),
            (99_003, 2, OperationAction::ReportRunning),
        ] {
            self.store
                .transition_operation(TransitionOperation {
                    context: RequestContext::new(
                        RequestId::from_uuid(Uuid::from_u128(request)).unwrap(),
                        owner,
                    ),
                    session_id: session,
                    epoch: lease.epoch(),
                    operation_id: operation,
                    expected_revision: Revision::new(revision).unwrap(),
                    action,
                    report_message_id: (action == OperationAction::ReportRunning)
                        .then_some(MessageId::from_uuid(Uuid::from_u128(825)).unwrap()),
                    terminal_outcome: None,
                })
                .await
                .map_err(|e| e.to_string())?;
        }
        self.store
            .release_ownership(ReleaseOwnership::new(
                RequestContext::new(
                    RequestId::from_uuid(Uuid::from_u128(99_004)).unwrap(),
                    owner,
                ),
                session,
                lease.epoch(),
            ))
            .await
            .map_err(|e| e.to_string())?;
        Ok((
            session,
            owner,
            ParticipantId::from_uuid(Uuid::from_u128(806)).unwrap(),
            operation,
        ))
    }
}

impl ToolStoreFixture for SqliteFixture {
    type Store = SqliteStore;
    fn store(&self) -> &Self::Store {
        &self.store
    }
    fn alternate_host(&self) -> HostId {
        HostId::from_uuid(Uuid::from_u128(120_999)).unwrap()
    }
    fn next_context(&mut self, caller: HostId) -> RequestContext {
        let id = self.next_tool_request;
        self.next_tool_request += 1;
        RequestContext::new(RequestId::from_uuid(Uuid::from_u128(id)).unwrap(), caller)
    }
    async fn reopen(&mut self) -> Result<(), StoreError> {
        self.store.pool().close().await;
        self.store = open(&self.path, self.clock.clone()).await?;
        Ok(())
    }
    async fn prepare_tool_invocation(
        &mut self,
    ) -> Result<
        (
            ReserveToolInvocation,
            navigator_store_api::ToolProviderConnectionSnapshot,
        ),
        String,
    > {
        let (session, owner, participant, operation) =
            EffectJournalFixture::prepare_linkage(self).await?;
        let epoch = self
            .store
            .acquire_ownership(AcquireOwnership::new(
                RequestContext::new(
                    RequestId::from_uuid(Uuid::from_u128(120_001)).unwrap(),
                    owner,
                ),
                session,
                LeaseDuration::from_millis(60_000).unwrap(),
            ))
            .await
            .map_err(|e| e.to_string())?
            .value()
            .epoch();
        let scope = ScopedCapability::new(
            Capability::new("tool.records.lookup").unwrap(),
            ResourceScope::Operation(operation),
        );
        let full = AuthorityProfile::new([scope.clone()], [scope]).unwrap();
        let policy_context = self.next_context(owner);
        self.store
            .put_authority_policy(PutAuthorityPolicy {
                context: policy_context,
                session_id: session,
                epoch,
                policy: AuthorityPolicySnapshot {
                    session_id: session,
                    participant_id: participant,
                    session: full.clone(),
                    parent: full.clone(),
                    template: full.clone(),
                    relationship: full.clone(),
                    subject: full,
                },
            })
            .await
            .map_err(|e| e.to_string())?;
        let definition=ToolDefinition::new(ToolName::new("records.lookup").unwrap(),ToolVersion::new("v1").unwrap(),
            CanonicalJson::<MAX_TOOL_SCHEMA_BYTES>::new(r#"{"additionalProperties":false,"properties":{"key":{"type":"string"}},"required":["key"],"type":"object"}"#).unwrap(),
            CanonicalJson::<MAX_TOOL_SCHEMA_BYTES>::new(r#"{"additionalProperties":false,"properties":{"found":{"type":"boolean"}},"required":["found"],"type":"object"}"#).unwrap(),
            Capability::new("tool.records.lookup").unwrap(),ToolTimeout::from_millis(10_000).unwrap(),ToolCancellation::Cooperative,
            EffectClass::Idempotent,IdempotencyContract::InvocationIdentity).unwrap();
        let registration_context = self.next_context(owner);
        self.store
            .register_tool(RegisterTool {
                context: registration_context,
                session_id: session,
                owner_epoch: epoch,
                registration_id: ToolRegistrationId::from_uuid(Uuid::from_u128(120_010)).unwrap(),
                consumer_key: ConsumerKey::new("operation-contract").unwrap(),
                definition,
            })
            .await
            .map_err(|e| e.to_string())?;
        let provider_id = ToolProviderId::from_uuid(Uuid::from_u128(120_011)).unwrap();
        let connect_context = self.next_context(owner);
        let connection = self
            .store
            .connect_tool_provider(ConnectToolProvider {
                context: connect_context,
                session_id: session,
                owner_epoch: epoch,
                consumer_key: ConsumerKey::new("operation-contract").unwrap(),
                provider_id,
                connection_id: ToolConnectionId::from_uuid(Uuid::from_u128(120_012)).unwrap(),
                after_server_sequence: 0,
                registration_ids: vec![
                    ToolRegistrationId::from_uuid(Uuid::from_u128(120_010)).unwrap(),
                ],
            })
            .await
            .map_err(|e| e.to_string())?;
        let request = RequestId::from_uuid(Uuid::from_u128(120_020)).unwrap();
        Ok((
            ReserveToolInvocation {
                context: RequestContext::new(request, owner),
                owner_epoch: epoch,
                dispatch_id: ToolDispatchId::from_uuid(Uuid::from_u128(120_022)).unwrap(),
                provider_id,
                registration_id: ToolRegistrationId::from_uuid(Uuid::from_u128(120_010)).unwrap(),
                deadline: Timestamp::new(205, 0).unwrap(),
                invocation: ToolInvocation::new(
                    ToolInvocationId::from_uuid(Uuid::from_u128(120_021)).unwrap(),
                    request,
                    session,
                    participant,
                    operation,
                    ToolName::new("records.lookup").unwrap(),
                    ToolVersion::new("v1").unwrap(),
                    CanonicalJson::<MAX_TOOL_INLINE_BYTES>::new(r#"{"key":"x"}"#).unwrap(),
                )
                .unwrap(),
                lease_duration: std::time::Duration::from_secs(10),
            },
            connection,
        ))
    }
}

impl InstanceStoreFixture for SqliteFixture {
    type Store = SqliteStore;

    fn store(&self) -> &Self::Store {
        &self.store
    }

    fn set_wall_seconds(&self, seconds: i64) {
        self.clock.set(seconds);
    }

    async fn reopen(&mut self) -> Result<(), StoreError> {
        self.store.pool().close().await;
        self.store = open(&self.path, self.clock.clone()).await?;
        Ok(())
    }
}

impl OperationStoreFixture for SqliteFixture {
    type Store = SqliteStore;

    fn store(&self) -> &Self::Store {
        &self.store
    }

    fn set_wall_seconds(&self, seconds: i64) {
        self.clock.set(seconds);
    }

    async fn reopen(&mut self) -> Result<(), StoreError> {
        self.store.pool().close().await;
        self.store = open(&self.path, self.clock.clone()).await?;
        Ok(())
    }

    async fn accept_causal_message(
        &self,
        session: SessionId,
        owner: HostId,
        epoch: FencingEpoch,
        participant: ParticipantId,
        message: MessageId,
    ) -> Result<(), String> {
        accept_operation_message(
            &self.store,
            session,
            owner,
            epoch,
            participant,
            message,
            88_000,
        )
        .await
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "conformance helper deliberately spells out the complete public launch, lease, pending, and accepted protocol without a Store bypass"
)]
async fn accept_operation_message(
    store: &SqliteStore,
    session: SessionId,
    owner: HostId,
    epoch: FencingEpoch,
    participant: ParticipantId,
    message: MessageId,
    base: u128,
) -> Result<(), String> {
    let participant_snapshot = store
        .load_participant(participant)
        .await
        .map_err(|error| error.to_string())?;
    let template = store
        .load_template(participant_snapshot.template_id)
        .await
        .map_err(|error| error.to_string())?;
    let attempt = LaunchAttemptId::from_uuid(Uuid::from_u128(base + 1)).unwrap();
    let instance = InstanceId::from_uuid(Uuid::from_u128(base + 2)).unwrap();
    store
        .prepare_launch(PrepareLaunch {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(base + 3)).unwrap(),
                owner,
            ),
            epoch,
            session_id: session,
            participant_id: participant,
            driver_id: template.driver.driver_id(),
            attempt_id: attempt,
            credential_digest: [31; 32],
            driver_configuration_digest: [32; 32],
        })
        .await
        .map_err(|error| error.to_string())?;
    store
        .attach_launch(AttachLaunch {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(base + 4)).unwrap(),
                owner,
            ),
            session_id: session,
            epoch,
            attempt_id: attempt,
            expected_revision: Revision::initial(),
            instance_id: instance,
            evidence: ProcessEvidence {
                process_id: 88,
                process_group_id: 88,
                parent_process_id: 1,
                creation_marker: 88,
                executable_identity: [33; 32],
            },
        })
        .await
        .map_err(|error| error.to_string())?;
    store
        .transition_launch(TransitionLaunch {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(base + 5)).unwrap(),
                owner,
            ),
            session_id: session,
            epoch,
            attempt_id: attempt,
            expected_revision: Revision::new(2).unwrap(),
            target: LaunchState::Ready,
            cleanup_reason: None,
        })
        .await
        .map_err(|error| error.to_string())?;
    let delivery_attempt = DeliveryAttemptId::from_uuid(Uuid::from_u128(base + 6)).unwrap();
    let leased = store
        .lease_next_message(LeaseNextMessage {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(base + 7)).unwrap(),
                owner,
            ),
            session_id: session,
            epoch,
            destination: participant,
            instance_id: instance,
            driver_launch_attempt_id: attempt,
            proposed_attempt_id: delivery_attempt,
            lease_duration: std::time::Duration::from_secs(10),
        })
        .await
        .map_err(|error| error.to_string())?
        .value()
        .clone()
        .ok_or_else(|| "causal Message was not leaseable".to_owned())?;
    if leased.message_id != message {
        return Err("leased a different causal Message".into());
    }
    let pending = store
        .transition_message_delivery(TransitionMessageDelivery {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(base + 8)).unwrap(),
                owner,
            ),
            session_id: session,
            epoch,
            message_id: message,
            attempt_id: delivery_attempt,
            expected_revision: leased.revision,
            transition: DeliveryTransition::AcceptancePending,
        })
        .await
        .map_err(|error| error.to_string())?
        .value()
        .clone();
    store
        .transition_message_delivery(TransitionMessageDelivery {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(base + 9)).unwrap(),
                owner,
            ),
            session_id: session,
            epoch,
            message_id: message,
            attempt_id: delivery_attempt,
            expected_revision: pending.revision,
            transition: DeliveryTransition::Accepted {
                proof_digest: [34; 32],
            },
        })
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

async fn accept_with_ready_launch(
    store: &SqliteStore,
    scope: MailboxScope,
    message: MessageId,
    request: u128,
) {
    let attempt_id = DeliveryAttemptId::from_uuid(Uuid::from_u128(request + 1)).unwrap();
    let leased = store
        .lease_next_message(LeaseNextMessage {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(request)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            destination: scope.destination,
            instance_id: scope.instance_id,
            driver_launch_attempt_id: scope.launch_attempt_id,
            proposed_attempt_id: attempt_id,
            lease_duration: std::time::Duration::from_secs(10),
        })
        .await
        .unwrap()
        .value()
        .clone()
        .unwrap();
    assert_eq!(leased.message_id, message);
    let pending = store
        .transition_message_delivery(TransitionMessageDelivery {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(request + 2)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            message_id: message,
            attempt_id,
            expected_revision: leased.revision,
            transition: DeliveryTransition::AcceptancePending,
        })
        .await
        .unwrap()
        .value()
        .clone();
    store
        .transition_message_delivery(TransitionMessageDelivery {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(request + 3)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            message_id: message,
            attempt_id,
            expected_revision: pending.revision,
            transition: DeliveryTransition::Accepted {
                proof_digest: [35; 32],
            },
        })
        .await
        .unwrap();
}

impl MailboxStoreFixture for SqliteFixture {
    type Store = SqliteStore;
    fn store(&self) -> &Self::Store {
        &self.store
    }
    fn set_wall_seconds(&self, seconds: i64) {
        self.clock.set(seconds);
    }
    async fn prepare(&self) -> Result<MailboxScope, StoreError> {
        let session_id = SessionId::from_uuid(Uuid::from_u128(7000)).unwrap();
        let owner = HostId::from_uuid(Uuid::from_u128(7001)).unwrap();
        let participant = ParticipantId::from_uuid(Uuid::from_u128(7002)).unwrap();
        let template_id = TemplateId::from_uuid(Uuid::from_u128(7003)).unwrap();
        let driver_id = DriverId::from_uuid(Uuid::from_u128(7004)).unwrap();
        let instance_id = InstanceId::from_uuid(Uuid::from_u128(7005)).unwrap();
        let template = Template::register(
            template_id,
            BoundedText::new("mailbox".to_owned()).unwrap(),
            DriverRequirement::new(driver_id, vec![]).unwrap(),
            TrustedConfiguration::new(BoundedText::new("trusted".to_owned()).unwrap(), []).unwrap(),
            ResourceBounds::new(1024, 1000, 1).unwrap(),
            InputSchema::new(vec![]).unwrap(),
        )
        .unwrap();
        let compatibility: CompatibilityIdentity = template.compatibility();
        self.store
            .open_session(OpenSession::new(
                RequestContext::new(RequestId::from_uuid(Uuid::from_u128(7010)).unwrap(), owner),
                session_id,
                ConsumerKey::new("mailbox-contract").unwrap(),
                compatibility,
            ))
            .await?;
        let epoch = self
            .store
            .acquire_ownership(AcquireOwnership::new(
                RequestContext::new(RequestId::from_uuid(Uuid::from_u128(7011)).unwrap(), owner),
                session_id,
                LeaseDuration::from_millis(60_000).unwrap(),
            ))
            .await?
            .value()
            .epoch();
        self.store
            .register_template(template.registration_snapshot())
            .await?;
        self.store
            .create_root_participant(CreateRootParticipant {
                context: RequestContext::new(
                    RequestId::from_uuid(Uuid::from_u128(7012)).unwrap(),
                    owner,
                ),
                session_id,
                epoch,
                participant_id: participant,
                template_id,
                expected_compatibility: compatibility,
            })
            .await?;
        let operation_id = OperationId::from_uuid(Uuid::from_u128(7014)).unwrap();
        let input_message_id = MessageId::from_uuid(Uuid::from_u128(20)).unwrap();
        let operation = self
            .store
            .start_operation(StartOperation {
                context: RequestContext::new(
                    RequestId::from_uuid(Uuid::from_u128(7015)).unwrap(),
                    owner,
                ),
                session_id,
                epoch,
                operation_id,
                participant_id: participant,
                input_message_id,
                input: template
                    .validate_input(br"{}")
                    .map_err(|_| StoreError::Invalid)?,
            })
            .await?
            .value()
            .clone();
        let launch_attempt_id =
            navigator_domain::LaunchAttemptId::from_uuid(Uuid::from_u128(7013)).unwrap();
        sqlx::query("INSERT INTO launch_attempts(attempt_id, session_id, ownership_epoch, participant_id, driver_id, instance_id, state, revision, credential_digest, evidence, cleanup_reason) VALUES (?, ?, ?, ?, ?, ?, 'ready', 1, ?, NULL, NULL)")
            .bind(launch_attempt_id.to_string()).bind(session_id.to_string()).bind(i64::try_from(epoch.get()).map_err(|_| StoreError::Corrupt)?).bind(participant.to_string()).bind(driver_id.to_string()).bind(instance_id.to_string()).bind(vec![1_u8;32]).execute(self.store.pool()).await.map_err(|_| StoreError::Corrupt)?;
        Ok(MailboxScope {
            session_id,
            owner,
            epoch,
            source: participant,
            destination: participant,
            instance_id,
            launch_attempt_id,
            operation_id,
            input_digest: operation.input_digest,
        })
    }
    async fn reopen(&mut self) -> Result<(), StoreError> {
        self.store.pool().close().await;
        self.store = open(&self.path, self.clock.clone()).await?;
        Ok(())
    }
}

impl TopologyStoreFixture for SqliteFixture {
    type Store = SqliteStore;
    fn store(&self) -> &Self::Store {
        &self.store
    }
    async fn prepare_scope(&self, seed: u128) -> Result<TopologyScope, StoreError> {
        let session_id = SessionId::from_uuid(Uuid::from_u128(seed + 1)).unwrap();
        let owner = HostId::from_uuid(Uuid::from_u128(seed + 2)).unwrap();
        let root = ParticipantId::from_uuid(Uuid::from_u128(seed + 3)).unwrap();
        let template_id = TemplateId::from_uuid(Uuid::from_u128(seed + 4)).unwrap();
        let driver_id = DriverId::from_uuid(Uuid::from_u128(seed + 5)).unwrap();
        let template = Template::register(
            template_id,
            BoundedText::new("topology".to_owned()).unwrap(),
            DriverRequirement::new(driver_id, vec![]).unwrap(),
            TrustedConfiguration::new(BoundedText::new("trusted".to_owned()).unwrap(), []).unwrap(),
            ResourceBounds::new(1024, 1000, 1).unwrap(),
            InputSchema::new(vec![]).unwrap(),
        )
        .unwrap();
        let compatibility = template.compatibility();
        self.store
            .open_session(OpenSession::new(
                RequestContext::new(
                    RequestId::from_uuid(Uuid::from_u128(seed + 10)).unwrap(),
                    owner,
                ),
                session_id,
                ConsumerKey::new(format!("topology-{seed}")).unwrap(),
                compatibility,
            ))
            .await?;
        let epoch = self
            .store
            .acquire_ownership(AcquireOwnership::new(
                RequestContext::new(
                    RequestId::from_uuid(Uuid::from_u128(seed + 11)).unwrap(),
                    owner,
                ),
                session_id,
                LeaseDuration::from_millis(60_000).unwrap(),
            ))
            .await?
            .value()
            .epoch();
        self.store
            .register_template(template.registration_snapshot())
            .await?;
        self.store
            .create_root_participant(CreateRootParticipant {
                context: RequestContext::new(
                    RequestId::from_uuid(Uuid::from_u128(seed + 12)).unwrap(),
                    owner,
                ),
                session_id,
                epoch,
                participant_id: root,
                template_id,
                expected_compatibility: compatibility,
            })
            .await?;
        Ok(TopologyScope {
            session_id,
            owner,
            epoch,
            root,
            template_id,
            compatibility,
        })
    }
    async fn reopen(&mut self) -> Result<(), StoreError> {
        self.store.pool().close().await;
        self.store = open(&self.path, self.clock.clone()).await?;
        Ok(())
    }
}

async fn open(path: &std::path::Path, clock: Arc<TrustedClock>) -> Result<SqliteStore, StoreError> {
    SqliteStore::open_with_clock(
        path,
        clock,
        LeaseDuration::from_millis(60_000).expect("valid contract maximum lease"),
    )
    .await
}

#[tokio::test]
async fn sqlite_obeys_shared_session_store_contract() {
    let mut fixture = SqliteFixture::new().await;
    assert_session_store_contract(&mut fixture)
        .await
        .expect("SQLite Store violated its semantic contract");
}

#[tokio::test]
async fn sqlite_obeys_shared_effect_journal_contract() {
    let mut fixture = SqliteFixture::new().await;
    assert_effect_journal_contract(&mut fixture)
        .await
        .expect("effect journal contract");
}

#[tokio::test]
async fn sqlite_obeys_shared_tool_store_contract() {
    let mut fixture = SqliteFixture::new().await;
    assert_tool_store_contract(&mut fixture)
        .await
        .expect("Tool Store contract");
}

#[tokio::test]
async fn effect_journal_corruption_fails_closed() {
    let mut fixture = SqliteFixture::new().await;
    assert_effect_journal_contract(&mut fixture)
        .await
        .expect("establish effect journal");
    let mut connection = fixture.store.pool().acquire().await.unwrap();
    sqlx::query("PRAGMA ignore_check_constraints = ON")
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::query("UPDATE effect_journal SET phase = 'invented' WHERE request_id = ?")
        .bind(
            RequestId::from_uuid(Uuid::from_u128(904))
                .unwrap()
                .to_string(),
        )
        .execute(&mut *connection)
        .await
        .unwrap();
    drop(connection);
    assert_eq!(
        fixture
            .store
            .read_effect(RequestId::from_uuid(Uuid::from_u128(904)).unwrap())
            .await,
        Err(StoreError::Corrupt)
    );
}

#[tokio::test]
async fn effect_journal_linkage_and_contract_corruption_fail_closed() {
    for column in [
        "participant_id",
        "resolution_contract",
        "semantic_resolution_contract",
    ] {
        let mut fixture = SqliteFixture::new().await;
        assert_effect_journal_contract(&mut fixture).await.unwrap();
        let mut connection = fixture.store.pool().acquire().await.unwrap();
        sqlx::query("PRAGMA foreign_keys=OFF")
            .execute(&mut *connection)
            .await
            .unwrap();
        let sql = if column == "participant_id" {
            "UPDATE effect_journal SET participant_id='00000000-0000-0000-0000-000000099999' WHERE request_id=?"
        } else if column == "semantic_resolution_contract" {
            r#"UPDATE effect_journal SET resolution_contract='{"allow_confirm_completed":true,"allow_do_not_retry":false,"allow_retry_with_proof":false,"allowed_proof_kinds":["effect_absent"]}' WHERE request_id=?"#
        } else {
            "UPDATE effect_journal SET resolution_contract=x'00' WHERE request_id=?"
        };
        sqlx::query(sql)
            .bind(
                RequestId::from_uuid(Uuid::from_u128(904))
                    .unwrap()
                    .to_string(),
            )
            .execute(&mut *connection)
            .await
            .unwrap();
        drop(connection);
        assert_eq!(
            fixture
                .store
                .read_effect(RequestId::from_uuid(Uuid::from_u128(904)).unwrap())
                .await,
            Err(StoreError::Corrupt)
        );
    }
}

#[tokio::test]
async fn sqlite_obeys_shared_instance_store_contract() {
    let mut fixture = SqliteFixture::new().await;
    assert_instance_store_contract(&mut fixture)
        .await
        .expect("SQLite Instance Store violated its semantic contract");
}

#[tokio::test]
async fn sqlite_obeys_shared_operation_store_contract() {
    let mut fixture = SqliteFixture::new().await;
    assert_operation_store_contract(&mut fixture)
        .await
        .expect("SQLite Operation Store violated its semantic contract");
    let stored: Vec<Vec<u8>> = sqlx::query_scalar("SELECT data FROM events")
        .fetch_all(fixture.store.pool())
        .await
        .expect("inspect persisted Event bytes independently");
    assert!(
        stored.iter().all(|data| !data
            .windows(PRIVATE_EVENT_SENTINEL.len())
            .any(|window| window == PRIVATE_EVENT_SENTINEL)),
        "private Operation result reached persisted Event bytes"
    );
}

#[tokio::test]
async fn sqlite_obeys_shared_mailbox_store_contract() {
    let mut fixture = SqliteFixture::new().await;
    assert_mailbox_store_contract(&mut fixture)
        .await
        .expect("SQLite Mailbox Store violated its semantic contract");
    let stored: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT data FROM events WHERE event_type LIKE 'message.%'")
            .fetch_all(fixture.store.pool())
            .await
            .expect("inspect persisted Message Event bytes independently");
    assert!(
        !stored.is_empty(),
        "Message facts were not persisted as Events"
    );
    for data in stored {
        let text = std::str::from_utf8(&data).expect("Event payload is canonical JSON");
        assert!(
            !["envelope", "input_digest", "proof_digest", "reason"]
                .iter()
                .any(|private| text.contains(private)),
            "private Message state reached persisted Event bytes"
        );
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the feedback oracle keeps retry, concurrency, and Event invariants in one lifecycle"
)]
async fn correlated_feedback_resumes_only_at_exact_durable_acceptance() {
    let fixture = SqliteFixture::new().await;
    let scope = MailboxStoreFixture::prepare(&fixture).await.unwrap();
    let mut operation = fixture
        .store
        .load_operation(scope.operation_id)
        .await
        .unwrap();
    accept_with_ready_launch(
        &fixture.store,
        scope,
        MessageId::from_uuid(Uuid::from_u128(20)).unwrap(),
        97_100,
    )
    .await;
    for (request, action, report) in [
        (97_000, OperationAction::BeginStart, None),
        (
            97_001,
            OperationAction::ReportRunning,
            Some(MessageId::from_uuid(Uuid::from_u128(20)).unwrap()),
        ),
    ] {
        operation = fixture
            .store
            .transition_operation(TransitionOperation {
                context: RequestContext::new(
                    RequestId::from_uuid(Uuid::from_u128(request)).unwrap(),
                    scope.owner,
                ),
                session_id: scope.session_id,
                epoch: scope.epoch,
                operation_id: scope.operation_id,
                expected_revision: operation.revision,
                action,
                report_message_id: report,
                terminal_outcome: None,
            })
            .await
            .unwrap()
            .value()
            .clone();
    }
    let question_id = MessageId::from_uuid(Uuid::from_u128(97_010)).unwrap();
    operation = fixture
        .store
        .transition_operation(TransitionOperation {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(97_002)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            operation_id: scope.operation_id,
            expected_revision: operation.revision,
            action: OperationAction::Wait,
            report_message_id: Some(question_id),
            terminal_outcome: None,
        })
        .await
        .unwrap()
        .value()
        .clone();
    fixture
        .store
        .enqueue_message(EnqueueMessage {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(97_003)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            message_id: question_id,
            source: scope.source,
            destination: scope.destination,
            correlation: MessageCorrelation {
                operation_id: Some(scope.operation_id),
                in_reply_to: None,
            },
            envelope: navigator_domain::ValidatedMessageEnvelope::question(
                scope.operation_id,
                Capability::new("input.required").unwrap(),
            ),
        })
        .await
        .unwrap();
    let feedback_id = MessageId::from_uuid(Uuid::from_u128(97_011)).unwrap();
    fixture
        .store
        .enqueue_message(EnqueueMessage {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(97_012)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            message_id: feedback_id,
            source: scope.source,
            destination: scope.destination,
            correlation: MessageCorrelation {
                operation_id: Some(scope.operation_id),
                in_reply_to: Some(question_id),
            },
            envelope: navigator_domain::ValidatedMessageEnvelope::correlated_feedback(
                scope.operation_id,
                question_id,
                FeedbackKind::Acknowledged,
            ),
        })
        .await
        .unwrap();
    let question_leased = fixture
        .store
        .lease_next_message(LeaseNextMessage {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(97_013)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            destination: scope.destination,
            instance_id: scope.instance_id,
            driver_launch_attempt_id: scope.launch_attempt_id,
            proposed_attempt_id: DeliveryAttemptId::from_uuid(Uuid::from_u128(97_014)).unwrap(),
            lease_duration: std::time::Duration::from_secs(10),
        })
        .await
        .unwrap()
        .value()
        .clone()
        .unwrap();
    let leased = question_leased;
    assert_eq!(leased.message_id, feedback_id);
    let MessageDeliveryState::Leased { lease } = &leased.state else {
        panic!("feedback was not leased");
    };
    let pending = fixture
        .store
        .transition_message_delivery(TransitionMessageDelivery {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(97_015)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            message_id: feedback_id,
            attempt_id: lease.attempt_id,
            expected_revision: leased.revision,
            transition: DeliveryTransition::AcceptancePending,
        })
        .await
        .unwrap()
        .value()
        .clone();
    assert_eq!(
        fixture
            .store
            .load_operation(scope.operation_id)
            .await
            .unwrap(),
        operation
    );
    let unknown = fixture
        .store
        .transition_message_delivery(TransitionMessageDelivery {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(97_017)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            message_id: feedback_id,
            attempt_id: lease.attempt_id,
            expected_revision: pending.revision,
            transition: DeliveryTransition::AcceptanceUnknown,
        })
        .await
        .unwrap()
        .value()
        .clone();
    assert_eq!(
        fixture
            .store
            .load_operation(scope.operation_id)
            .await
            .unwrap(),
        operation
    );
    let retry = fixture
        .store
        .transition_message_delivery(TransitionMessageDelivery {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(97_018)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            message_id: feedback_id,
            attempt_id: lease.attempt_id,
            expected_revision: unknown.revision,
            transition: DeliveryTransition::RetryAfter {
                delay: std::time::Duration::from_secs(1),
            },
        })
        .await
        .unwrap()
        .value()
        .clone();
    assert_eq!(
        fixture
            .store
            .load_operation(scope.operation_id)
            .await
            .unwrap(),
        operation
    );
    assert_eq!(
        fixture
            .store
            .transition_message_delivery(TransitionMessageDelivery {
                context: RequestContext::new(
                    RequestId::from_uuid(Uuid::from_u128(97_019)).unwrap(),
                    scope.owner
                ),
                session_id: scope.session_id,
                epoch: scope.epoch,
                message_id: feedback_id,
                attempt_id: lease.attempt_id,
                expected_revision: retry.revision,
                transition: DeliveryTransition::Accepted {
                    proof_digest: [9; 32]
                },
            })
            .await,
        Err(StoreError::Invalid)
    );
    fixture.clock.set(102);
    let released = fixture
        .store
        .lease_next_message(LeaseNextMessage {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(97_020)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            destination: scope.destination,
            instance_id: scope.instance_id,
            driver_launch_attempt_id: scope.launch_attempt_id,
            proposed_attempt_id: DeliveryAttemptId::from_uuid(Uuid::from_u128(97_021)).unwrap(),
            lease_duration: std::time::Duration::from_secs(10),
        })
        .await
        .unwrap()
        .value()
        .clone()
        .unwrap();
    let MessageDeliveryState::Leased {
        lease: replacement_lease,
    } = &released.state
    else {
        panic!("feedback was not re-leased");
    };
    let replacement_pending = fixture
        .store
        .transition_message_delivery(TransitionMessageDelivery {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(97_022)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            message_id: feedback_id,
            attempt_id: replacement_lease.attempt_id,
            expected_revision: released.revision,
            transition: DeliveryTransition::AcceptancePending,
        })
        .await
        .unwrap()
        .value()
        .clone();
    let accepted_command = TransitionMessageDelivery {
        context: RequestContext::new(
            RequestId::from_uuid(Uuid::from_u128(97_016)).unwrap(),
            scope.owner,
        ),
        session_id: scope.session_id,
        epoch: scope.epoch,
        message_id: feedback_id,
        attempt_id: replacement_lease.attempt_id,
        expected_revision: replacement_pending.revision,
        transition: DeliveryTransition::Accepted {
            proof_digest: [9; 32],
        },
    };
    let (left, right) = tokio::join!(
        fixture
            .store
            .transition_message_delivery(accepted_command.clone()),
        fixture
            .store
            .transition_message_delivery(accepted_command.clone()),
    );
    let applied = [left.unwrap(), right.unwrap()];
    assert!(applied.iter().any(|result| !result.was_replayed()));
    assert!(
        applied
            .iter()
            .any(navigator_store_api::Mutation::was_replayed)
    );
    let resumed = fixture
        .store
        .load_operation(scope.operation_id)
        .await
        .unwrap();
    assert_eq!(resumed.state, navigator_domain::OperationState::Running);
    assert_eq!(resumed.waiting_on_message_id, None);
    assert_eq!(resumed.revision.get(), operation.revision.get() + 1);
    assert!(matches!(
        fixture.store.load_message(feedback_id).await.unwrap().state,
        MessageDeliveryState::Accepted { .. }
    ));
    let events = fixture
        .store
        .read_events(navigator_store_api::ReadEvents {
            session_id: scope.session_id,
            consumer: ConsumerKey::new("mailbox-contract").unwrap(),
            after: None,
            limit: navigator_store_api::EventReadLimit::new(128).unwrap(),
        })
        .await
        .unwrap();
    assert_eq!(
        events
            .events
            .iter()
            .filter(|event| event.event_type().as_str() == "operation.resumed")
            .count(),
        1
    );
}

#[tokio::test]
async fn cancellation_is_durable_subtree_scoped_and_cleanup_is_not_optimistic() {
    let CancellationScenario {
        fixture,
        scope,
        template,
        child,
        grandchild,
        running,
        grand_operation,
        sibling_operation,
        command,
    } = prepare_cancellation_scenario().await;
    let cancelled = fixture.store.cancel_subtree(command.clone()).await.unwrap();
    let messages_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages")
        .fetch_one(fixture.store.pool())
        .await
        .unwrap();
    let inspected = fixture
        .store
        .inspect_subtree_cancellation(scope.session_id, child)
        .await
        .unwrap();
    assert_eq!(inspected, *cancelled.value());
    let messages_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages")
        .fetch_one(fixture.store.pool())
        .await
        .unwrap();
    assert_eq!(messages_after, messages_before);
    assert_eq!(cancelled.value().records.len(), 2);
    let child_record = cancelled
        .value()
        .records
        .iter()
        .find(|record| record.operation.operation_id == running.operation_id)
        .unwrap();
    assert_eq!(
        child_record.operation.state,
        navigator_domain::OperationState::Cancelling
    );
    assert!(child_record.notification.is_some());
    assert!(!child_record.cleanup_confirmed());
    let grand_record = cancelled
        .value()
        .records
        .iter()
        .find(|record| record.operation.operation_id == grand_operation.operation_id)
        .unwrap();
    assert_eq!(
        grand_record.operation.state,
        navigator_domain::OperationState::Cancelled
    );
    assert!(grand_record.notification.is_none());
    assert!(grand_record.cleanup_confirmed());
    assert_eq!(
        fixture
            .store
            .load_operation(sibling_operation.operation_id)
            .await
            .unwrap(),
        sibling_operation
    );
    assert_cancellation_replay_and_late_rule(
        &fixture,
        scope,
        child,
        &running,
        child_record.operation.revision,
        command,
    )
    .await;
    assert_cancelled_scope_rejects_new_work(&fixture, scope, &template, child, grandchild).await;
}

async fn assert_cancellation_replay_and_late_rule(
    fixture: &SqliteFixture,
    scope: TopologyScope,
    child: ParticipantId,
    running: &navigator_store_api::OperationSnapshot,
    cancellation_revision: navigator_domain::Revision,
    command: CancelSubtree,
) {
    let replayed = fixture.store.cancel_subtree(command).await.unwrap();
    assert!(replayed.was_replayed());
    assert_eq!(replayed.value().records.len(), 2);
    let transition = |request, action, terminal_outcome| TransitionOperation {
        context: RequestContext::new(
            RequestId::from_uuid(Uuid::from_u128(request)).unwrap(),
            scope.owner,
        ),
        session_id: scope.session_id,
        epoch: scope.epoch,
        operation_id: running.operation_id,
        expected_revision: cancellation_revision,
        action,
        report_message_id: Some(running.input_message_id),
        terminal_outcome,
    };
    assert_eq!(
        fixture
            .store
            .transition_operation(transition(
                120_241,
                OperationAction::ReportSuccess,
                Some(navigator_store_api::OperationTerminalOutcome::Succeeded {
                    result: navigator_domain::BoundedBytes::new(Vec::new()).unwrap(),
                }),
            ))
            .await,
        Err(StoreError::Invalid)
    );
    let terminal = fixture
        .store
        .transition_operation(transition(
            120_242,
            OperationAction::ReportCancelled,
            Some(navigator_store_api::OperationTerminalOutcome::Cancelled),
        ))
        .await
        .unwrap()
        .value()
        .clone();
    let current = fixture
        .store
        .cancel_subtree(CancelSubtree {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(120_243)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            root_participant_id: child,
        })
        .await
        .unwrap();
    assert!(current.value().records.iter().any(|record| {
        record.operation.operation_id == terminal.operation_id
            && record.operation.state == navigator_domain::OperationState::Cancelled
    }));
    let terminal_with_pending_notification = current
        .value()
        .records
        .iter()
        .find(|record| record.operation.operation_id == terminal.operation_id)
        .unwrap();
    assert!(terminal_with_pending_notification.notification.is_some());
    assert!(!terminal_with_pending_notification.cleanup_confirmed());
}

async fn assert_cancelled_scope_rejects_new_work(
    fixture: &SqliteFixture,
    scope: TopologyScope,
    template: &Template,
    child: ParticipantId,
    grandchild: ParticipantId,
) {
    let denied_start = StartOperation {
        context: RequestContext::new(
            RequestId::from_uuid(Uuid::from_u128(120_250)).unwrap(),
            scope.owner,
        ),
        session_id: scope.session_id,
        epoch: scope.epoch,
        operation_id: OperationId::from_uuid(Uuid::from_u128(120_251)).unwrap(),
        participant_id: grandchild,
        input_message_id: MessageId::from_uuid(Uuid::from_u128(120_252)).unwrap(),
        input: template.validate_input(b"{}").unwrap(),
    };
    assert_eq!(
        fixture.store.start_operation(denied_start.clone()).await,
        Err(StoreError::Invalid)
    );
    assert_eq!(
        fixture.store.start_operation(denied_start).await,
        Err(StoreError::Invalid)
    );
    assert_eq!(
        fixture
            .store
            .create_child_participant(CreateChildParticipant {
                context: RequestContext::new(
                    RequestId::from_uuid(Uuid::from_u128(120_260)).unwrap(),
                    scope.owner
                ),
                session_id: scope.session_id,
                epoch: scope.epoch,
                participant_id: ParticipantId::from_uuid(Uuid::from_u128(120_261)).unwrap(),
                parent_participant_id: grandchild,
                template_id: scope.template_id,
                expected_compatibility: scope.compatibility,
            })
            .await,
        Err(StoreError::Invalid)
    );
    let controls = fixture
        .store
        .load_mailbox(child)
        .await
        .unwrap()
        .into_iter()
        .filter(|message| {
            matches!(
                message.envelope.body(),
                navigator_domain::MessageBody::Control {
                    command: navigator_domain::ControlMessageKind::Cancel,
                    ..
                }
            )
        })
        .count();
    assert_eq!(controls, 1);
}

struct CancellationScenario {
    fixture: SqliteFixture,
    scope: TopologyScope,
    template: Template,
    child: ParticipantId,
    grandchild: ParticipantId,
    running: navigator_store_api::OperationSnapshot,
    grand_operation: navigator_store_api::OperationSnapshot,
    sibling_operation: navigator_store_api::OperationSnapshot,
    command: CancelSubtree,
}

async fn prepare_cancellation_scenario() -> CancellationScenario {
    let fixture = SqliteFixture::new().await;
    let scope = fixture.prepare_scope(120_000).await.unwrap();
    let child = ParticipantId::from_uuid(Uuid::from_u128(120_101)).unwrap();
    let sibling = ParticipantId::from_uuid(Uuid::from_u128(120_102)).unwrap();
    let grandchild = ParticipantId::from_uuid(Uuid::from_u128(120_103)).unwrap();
    for (request, participant, parent) in [
        (121_010, child, scope.root),
        (121_011, sibling, scope.root),
        (121_012, grandchild, child),
    ] {
        fixture
            .store
            .create_child_participant(CreateChildParticipant {
                context: RequestContext::new(
                    RequestId::from_uuid(Uuid::from_u128(request)).unwrap(),
                    scope.owner,
                ),
                session_id: scope.session_id,
                epoch: scope.epoch,
                participant_id: participant,
                parent_participant_id: parent,
                template_id: scope.template_id,
                expected_compatibility: scope.compatibility,
            })
            .await
            .unwrap();
    }
    let template = Template::try_from(
        fixture
            .store
            .load_template(scope.template_id)
            .await
            .unwrap(),
    )
    .unwrap();
    let child_operation = start_test_operation(&fixture, scope, &template, child, 120_200).await;
    let grand_operation =
        start_test_operation(&fixture, scope, &template, grandchild, 120_210).await;
    let sibling_operation =
        start_test_operation(&fixture, scope, &template, sibling, 120_220).await;
    accept_operation_message(
        &fixture.store,
        scope.session_id,
        scope.owner,
        scope.epoch,
        child,
        child_operation.input_message_id,
        120_300,
    )
    .await
    .unwrap();
    let mut running = child_operation;
    for (request, action) in [
        (120_230, OperationAction::BeginStart),
        (120_231, OperationAction::ReportRunning),
    ] {
        running = fixture
            .store
            .transition_operation(TransitionOperation {
                context: RequestContext::new(
                    RequestId::from_uuid(Uuid::from_u128(request)).unwrap(),
                    scope.owner,
                ),
                session_id: scope.session_id,
                epoch: scope.epoch,
                operation_id: running.operation_id,
                expected_revision: running.revision,
                action,
                report_message_id: (action == OperationAction::ReportRunning)
                    .then_some(running.input_message_id),
                terminal_outcome: None,
            })
            .await
            .unwrap()
            .value()
            .clone();
    }
    let command = CancelSubtree {
        context: RequestContext::new(
            RequestId::from_uuid(Uuid::from_u128(120_240)).unwrap(),
            scope.owner,
        ),
        session_id: scope.session_id,
        epoch: scope.epoch,
        root_participant_id: child,
    };
    CancellationScenario {
        fixture,
        scope,
        template,
        child,
        grandchild,
        running,
        grand_operation,
        sibling_operation,
        command,
    }
}

async fn start_test_operation(
    fixture: &SqliteFixture,
    scope: TopologyScope,
    template: &Template,
    participant_id: ParticipantId,
    seed: u128,
) -> navigator_store_api::OperationSnapshot {
    fixture
        .store
        .start_operation(StartOperation {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(seed)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            operation_id: OperationId::from_uuid(Uuid::from_u128(seed + 1)).unwrap(),
            participant_id,
            input_message_id: MessageId::from_uuid(Uuid::from_u128(seed + 2)).unwrap(),
            input: template.validate_input(b"{}").unwrap(),
        })
        .await
        .unwrap()
        .value()
        .clone()
}

#[tokio::test]
async fn sqlite_obeys_shared_topology_store_contract() {
    let mut fixture = SqliteFixture::new().await;
    assert_topology_store_contract(&mut fixture)
        .await
        .expect("SQLite topology contract");
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "single authority lifecycle semantic matrix"
)]
async fn authority_grants_are_fenced_expiring_revocable_and_single_use() {
    let fixture = SqliteFixture::new().await;
    let scope = fixture.prepare_scope(90_000).await.unwrap();
    let requested = ScopedCapability::new(
        Capability::new("participant.spawn").unwrap(),
        ResourceScope::Participant(scope.root),
    );
    let full = AuthorityProfile::new([requested.clone()], [requested.clone()]).unwrap();
    let policy = AuthorityPolicySnapshot {
        session_id: scope.session_id,
        participant_id: scope.root,
        session: full.clone(),
        parent: full.clone(),
        template: full.clone(),
        relationship: full.clone(),
        subject: full.clone(),
    };
    fixture
        .store
        .put_authority_policy(PutAuthorityPolicy {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(90_100)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            policy,
        })
        .await
        .unwrap();
    let grant_id = GrantId::from_uuid(Uuid::from_u128(90_101)).unwrap();
    fixture
        .store
        .issue_grant(IssueGrant {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(90_102)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            grant: Grant {
                id: grant_id,
                session_id: scope.session_id,
                subject: scope.root,
                authority: requested.clone(),
                expires_at: Timestamp::new(110, 0).unwrap(),
                revoked: false,
            },
            single_use: true,
        })
        .await
        .unwrap();
    let check = |request| CheckAuthorityEffect {
        context: RequestContext::new(
            RequestId::from_uuid(Uuid::from_u128(request)).unwrap(),
            scope.owner,
        ),
        session_id: scope.session_id,
        epoch: scope.epoch,
        participant_id: scope.root,
        requested: requested.clone(),
        grant_id: Some(grant_id),
    };
    let (left, right) = tokio::join!(
        fixture.store.check_authority_effect(check(90_103)),
        fixture.store.check_authority_effect(check(90_104)),
    );
    let outcomes = [
        left.unwrap().value().clone(),
        right.unwrap().value().clone(),
    ];
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| matches!(value, AuthorityEffectOutcome::Allowed { .. }))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| matches!(value, AuthorityEffectOutcome::Denied))
            .count(),
        1
    );
    let consumed: GrantSnapshot = fixture.store.load_grant(grant_id).await.unwrap();
    assert!(consumed.consumed_at.is_some());
    let replay = fixture
        .store
        .check_authority_effect(check(90_103))
        .await
        .unwrap();
    assert!(replay.was_replayed());

    let revoke_id = GrantId::from_uuid(Uuid::from_u128(90_105)).unwrap();
    fixture
        .store
        .issue_grant(IssueGrant {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(90_106)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            grant: Grant {
                id: revoke_id,
                session_id: scope.session_id,
                subject: scope.root,
                authority: requested.clone(),
                expires_at: Timestamp::new(110, 0).unwrap(),
                revoked: false,
            },
            single_use: false,
        })
        .await
        .unwrap();
    fixture
        .store
        .revoke_grant(RevokeGrant {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(90_107)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            grant_id: revoke_id,
        })
        .await
        .unwrap();
    let mut revoked_check = check(90_108);
    revoked_check.grant_id = Some(revoke_id);
    assert_eq!(
        *fixture
            .store
            .check_authority_effect(revoked_check)
            .await
            .unwrap()
            .value(),
        AuthorityEffectOutcome::Denied
    );

    fixture.clock.set(110);
    let expired_id = GrantId::from_uuid(Uuid::from_u128(90_109)).unwrap();
    let expired = Grant {
        id: expired_id,
        session_id: scope.session_id,
        subject: scope.root,
        authority: requested,
        expires_at: Timestamp::new(110, 0).unwrap(),
        revoked: false,
    };
    assert_eq!(
        fixture
            .store
            .issue_grant(IssueGrant {
                context: RequestContext::new(
                    RequestId::from_uuid(Uuid::from_u128(90_110)).unwrap(),
                    scope.owner
                ),
                session_id: scope.session_id,
                epoch: scope.epoch,
                grant: expired,
                single_use: false,
            })
            .await,
        Err(StoreError::Invalid)
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "single atomic spawn and replay semantic matrix"
)]
async fn authorized_spawn_consumes_single_use_grant_only_with_atomic_child_and_policy() {
    let fixture = SqliteFixture::new().await;
    let scope = fixture.prepare_scope(95_000).await.unwrap();
    let requested = ScopedCapability::new(
        Capability::new("participant.spawn").unwrap(),
        ResourceScope::Participant(scope.root),
    );
    let status_left = ScopedCapability::new(
        Capability::new("participant.status").unwrap(),
        ResourceScope::Participant(ParticipantId::from_uuid(Uuid::from_u128(95_104)).unwrap()),
    );
    let status_right = ScopedCapability::new(
        Capability::new("participant.status").unwrap(),
        ResourceScope::Participant(ParticipantId::from_uuid(Uuid::from_u128(95_106)).unwrap()),
    );
    let child_left = ParticipantId::from_uuid(Uuid::from_u128(95_104)).unwrap();
    let child_right = ParticipantId::from_uuid(Uuid::from_u128(95_106)).unwrap();
    let operation_left = OperationId::from_uuid(Uuid::from_u128(95_204)).unwrap();
    let operation_right = OperationId::from_uuid(Uuid::from_u128(95_206)).unwrap();
    let root_operation = OperationId::from_uuid(Uuid::from_u128(95_900)).unwrap();
    let mut rules = vec![requested.clone(), status_left, status_right];
    for operation in [operation_left, operation_right, root_operation] {
        for capability in [
            "message.question",
            "message.outcome",
            "operation.cancel",
            "operation.resume",
        ] {
            rules.push(ScopedCapability::new(
                Capability::new(capability).unwrap(),
                ResourceScope::Operation(operation),
            ));
        }
    }
    for participant in [scope.root, child_left, child_right] {
        rules.push(ScopedCapability::new(
            Capability::new("message.send").unwrap(),
            ResourceScope::Participant(participant),
        ));
    }
    let full = AuthorityProfile::new(rules.clone(), rules).unwrap();
    let parent_policy = AuthorityPolicySnapshot {
        session_id: scope.session_id,
        participant_id: scope.root,
        session: full.clone(),
        parent: full.clone(),
        template: full.clone(),
        relationship: full.clone(),
        subject: full.clone(),
    };
    fixture
        .store
        .put_authority_policy(PutAuthorityPolicy {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(95_100)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            policy: parent_policy,
        })
        .await
        .unwrap();
    fixture
        .store
        .register_authority_template_policy(RegisterAuthorityTemplatePolicy {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(95_099)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            policy: AuthorityTemplatePolicy {
                template_id: scope.template_id,
                allowed_parent_templates: [scope.template_id].into_iter().collect(),
                template: full.clone(),
                relationship: full.clone(),
                subject: full.clone(),
            },
        })
        .await
        .unwrap();
    let input = Template::try_from(
        fixture
            .store
            .load_template(scope.template_id)
            .await
            .unwrap(),
    )
    .unwrap()
    .validate_input(br"{}")
    .unwrap();
    fixture
        .store
        .start_operation(StartOperation {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(95_901)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            operation_id: root_operation,
            participant_id: scope.root,
            input_message_id: MessageId::from_uuid(Uuid::from_u128(95_902)).unwrap(),
            input: input.clone(),
        })
        .await
        .unwrap();
    let grant_id = GrantId::from_uuid(Uuid::from_u128(95_101)).unwrap();
    fixture
        .store
        .issue_grant(IssueGrant {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(95_102)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            grant: Grant {
                id: grant_id,
                session_id: scope.session_id,
                subject: scope.root,
                authority: requested.clone(),
                expires_at: Timestamp::new(120, 0).unwrap(),
                revoked: false,
            },
            single_use: true,
        })
        .await
        .unwrap();
    let spawn = |request: u128, child_value: u128| {
        let child_id = ParticipantId::from_uuid(Uuid::from_u128(child_value)).unwrap();
        CreateAuthorizedChild {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(request)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            parent_participant_id: scope.root,
            participant_id: child_id,
            template_id: scope.template_id,
            expected_compatibility: scope.compatibility,
            requested: requested.clone(),
            grant_id: Some(grant_id),
            operation_id: OperationId::from_uuid(Uuid::from_u128(child_value + 100)).unwrap(),
            input_message_id: MessageId::from_uuid(Uuid::from_u128(child_value + 200)).unwrap(),
            input: input.clone(),
        }
    };
    let left_command = spawn(95_103, 95_104);
    let right_command = spawn(95_105, 95_106);
    let (left, right) = tokio::join!(
        fixture.store.create_authorized_child(left_command.clone()),
        fixture.store.create_authorized_child(right_command.clone())
    );
    let left = left.unwrap();
    let right = right.unwrap();
    let outcomes = [left.value().clone(), right.value().clone()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| matches!(value, AuthorizedChildOutcome::Allowed { .. }))
            .count(),
        1
    );
    let (applied, original, denied) =
        if matches!(left.value(), AuthorizedChildOutcome::Allowed { .. }) {
            (left.value().clone(), left_command, right_command)
        } else {
            (right.value().clone(), right_command, left_command)
        };
    let replay = fixture
        .store
        .create_authorized_child(CreateAuthorizedChild {
            participant_id: ParticipantId::from_uuid(Uuid::from_u128(95_900)).unwrap(),
            operation_id: OperationId::from_uuid(Uuid::from_u128(95_901)).unwrap(),
            input_message_id: MessageId::from_uuid(Uuid::from_u128(95_902)).unwrap(),
            ..original.clone()
        })
        .await
        .unwrap();
    assert!(matches!(replay, navigator_store_api::Mutation::Replayed(_)));
    assert_eq!(replay.value(), &applied);
    let AuthorizedChildOutcome::Allowed {
        participant,
        operation,
        ..
    } = &applied
    else {
        unreachable!("selected applied outcome")
    };
    let status = |request, target, operation_id, epoch| AuthorizedStatus {
        context: RequestContext::new(
            RequestId::from_uuid(Uuid::from_u128(request)).unwrap(),
            scope.owner,
        ),
        session_id: scope.session_id,
        epoch,
        caller_participant_id: scope.root,
        target_participant_id: target,
        operation_id,
    };
    let initial_status_command = status(
        95_950,
        participant.participant_id,
        Some(operation.operation_id),
        scope.epoch,
    );
    let initial_status = fixture
        .store
        .authorized_status(initial_status_command.clone())
        .await
        .unwrap();
    assert!(matches!(
        initial_status.value(),
        AuthorizedStatusOutcome::Allowed { .. }
    ));
    assert_eq!(
        fixture
            .store
            .authorized_status(status(
                95_951,
                ParticipantId::from_uuid(Uuid::from_u128(95_999)).unwrap(),
                None,
                scope.epoch,
            ))
            .await
            .unwrap()
            .value(),
        &AuthorizedStatusOutcome::Denied
    );
    assert_eq!(
        fixture
            .store
            .authorized_status(status(
                95_952,
                participant.participant_id,
                Some(OperationId::from_uuid(Uuid::from_u128(95_998)).unwrap()),
                scope.epoch,
            ))
            .await
            .unwrap()
            .value(),
        &AuthorizedStatusOutcome::Denied
    );
    assert_eq!(
        fixture
            .store
            .authorized_status(status(
                95_953,
                participant.participant_id,
                None,
                FencingEpoch::new(scope.epoch.get() + 1).unwrap(),
            ))
            .await
            .unwrap()
            .value(),
        &AuthorizedStatusOutcome::Denied
    );
    let mut child_operation = operation.as_ref().clone();
    accept_operation_message(
        &fixture.store,
        scope.session_id,
        scope.owner,
        scope.epoch,
        participant.participant_id,
        child_operation.input_message_id,
        96_100,
    )
    .await
    .unwrap();
    for (request, action) in [
        (96_000, OperationAction::BeginStart),
        (96_001, OperationAction::ReportRunning),
    ] {
        child_operation = fixture
            .store
            .transition_operation(TransitionOperation {
                context: RequestContext::new(
                    RequestId::from_uuid(Uuid::from_u128(request)).unwrap(),
                    scope.owner,
                ),
                session_id: scope.session_id,
                epoch: scope.epoch,
                operation_id: child_operation.operation_id,
                expected_revision: child_operation.revision,
                action,
                report_message_id: (action == OperationAction::ReportRunning)
                    .then_some(child_operation.input_message_id),
                terminal_outcome: None,
            })
            .await
            .unwrap()
            .value()
            .clone();
    }
    let progressed_spawn_replay = fixture
        .store
        .create_authorized_child(original.clone())
        .await
        .unwrap();
    assert!(matches!(
        progressed_spawn_replay,
        navigator_store_api::Mutation::Replayed(_)
    ));
    assert_eq!(progressed_spawn_replay.value(), &applied);
    let replayed_status = fixture
        .store
        .authorized_status(initial_status_command.clone())
        .await
        .unwrap();
    assert!(matches!(
        replayed_status,
        navigator_store_api::Mutation::Replayed(_)
    ));
    assert_eq!(replayed_status.value(), initial_status.value());
    assert!(matches!(
        fixture
            .store
            .authorized_status(AuthorizedStatus {
                target_participant_id: scope.root,
                ..initial_status_command
            })
            .await,
        Err(StoreError::RequestConflict { .. })
    ));
    let question_id = MessageId::from_uuid(Uuid::from_u128(96_010)).unwrap();
    let question = fixture
        .store
        .apply_hierarchy_effect(ApplyHierarchyEffect {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(96_011)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            caller_participant_id: participant.participant_id,
            effect: HierarchyEffect::QuestionUpward {
                message_id: question_id,
                operation_id: child_operation.operation_id,
                delivered_message_id: child_operation.input_message_id,
                code: Capability::new("input.required").unwrap(),
                grant_id: None,
            },
        })
        .await
        .unwrap();
    assert!(
        matches!(question.value(), HierarchyEffectOutcome::Allowed { operation: Some(value), .. }
        if value.waiting_on_message_id == Some(question_id))
    );
    let wrong_resume = fixture
        .store
        .apply_hierarchy_effect(ApplyHierarchyEffect {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(96_012)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            caller_participant_id: scope.root,
            effect: HierarchyEffect::ResumeChild {
                message_id: MessageId::from_uuid(Uuid::from_u128(96_013)).unwrap(),
                child_id: participant.participant_id,
                operation_id: child_operation.operation_id,
                in_reply_to: MessageId::from_uuid(Uuid::from_u128(96_014)).unwrap(),
                feedback: FeedbackKind::Acknowledged,
                grant_id: None,
            },
        })
        .await
        .unwrap();
    assert_eq!(wrong_resume.value(), &HierarchyEffectOutcome::Denied);
    let resume = fixture
        .store
        .apply_hierarchy_effect(ApplyHierarchyEffect {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(96_015)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            caller_participant_id: scope.root,
            effect: HierarchyEffect::ResumeChild {
                message_id: MessageId::from_uuid(Uuid::from_u128(96_016)).unwrap(),
                child_id: participant.participant_id,
                operation_id: child_operation.operation_id,
                in_reply_to: question_id,
                feedback: FeedbackKind::Acknowledged,
                grant_id: None,
            },
        })
        .await
        .unwrap();
    assert!(
        matches!(resume.value(), HierarchyEffectOutcome::Allowed { operation: Some(value), .. }
        if value.state == navigator_domain::OperationState::Waiting && value.waiting_on_message_id == Some(question_id))
    );
    let forged_direction = fixture
        .store
        .apply_hierarchy_effect(ApplyHierarchyEffect {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(96_017)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            caller_participant_id: participant.participant_id,
            effect: HierarchyEffect::CancelChild {
                message_id: MessageId::from_uuid(Uuid::from_u128(96_018)).unwrap(),
                child_id: scope.root,
                operation_id: root_operation,
                grant_id: None,
            },
        })
        .await
        .unwrap();
    assert_eq!(forged_direction.value(), &HierarchyEffectOutcome::Denied);
    let send_context = RequestContext::new(
        RequestId::from_uuid(Uuid::from_u128(96_019)).unwrap(),
        scope.owner,
    );
    let send = fixture
        .store
        .apply_hierarchy_effect(ApplyHierarchyEffect {
            context: send_context,
            session_id: scope.session_id,
            epoch: scope.epoch,
            caller_participant_id: scope.root,
            effect: HierarchyEffect::Send {
                message_id: MessageId::from_uuid(Uuid::from_u128(96_020)).unwrap(),
                destination: participant.participant_id,
                envelope: navigator_domain::ValidatedMessageEnvelope::control(
                    child_operation.operation_id,
                    navigator_domain::ControlMessageKind::Reminder,
                ),
                grant_id: None,
            },
        })
        .await
        .unwrap();
    assert!(matches!(
        send.value(),
        HierarchyEffectOutcome::Allowed { .. }
    ));
    let send_replay = fixture
        .store
        .apply_hierarchy_effect(ApplyHierarchyEffect {
            context: send_context,
            session_id: scope.session_id,
            epoch: scope.epoch,
            caller_participant_id: scope.root,
            effect: HierarchyEffect::Send {
                message_id: MessageId::from_uuid(Uuid::from_u128(96_021)).unwrap(),
                destination: participant.participant_id,
                envelope: navigator_domain::ValidatedMessageEnvelope::control(
                    child_operation.operation_id,
                    navigator_domain::ControlMessageKind::Reminder,
                ),
                grant_id: None,
            },
        })
        .await
        .unwrap();
    assert!(matches!(
        send_replay,
        navigator_store_api::Mutation::Replayed(_)
    ));
    assert_eq!(send_replay.value(), send.value());
    let cancel = fixture
        .store
        .apply_hierarchy_effect(ApplyHierarchyEffect {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(96_022)).unwrap(),
                scope.owner,
            ),
            session_id: scope.session_id,
            epoch: scope.epoch,
            caller_participant_id: scope.root,
            effect: HierarchyEffect::CancelChild {
                message_id: MessageId::from_uuid(Uuid::from_u128(96_023)).unwrap(),
                child_id: participant.participant_id,
                operation_id: child_operation.operation_id,
                grant_id: None,
            },
        })
        .await
        .unwrap();
    assert!(
        matches!(cancel.value(), HierarchyEffectOutcome::Allowed { operation: Some(value), .. }
        if value.state == navigator_domain::OperationState::Cancelling)
    );
    let cancelling_spawn_replay = fixture
        .store
        .create_authorized_child(original.clone())
        .await
        .unwrap();
    assert!(matches!(
        cancelling_spawn_replay,
        navigator_store_api::Mutation::Replayed(_)
    ));
    assert_eq!(cancelling_spawn_replay.value(), &applied);
    let denied_replay = fixture
        .store
        .create_authorized_child(CreateAuthorizedChild {
            participant_id: ParticipantId::from_uuid(Uuid::from_u128(95_910)).unwrap(),
            operation_id: OperationId::from_uuid(Uuid::from_u128(95_911)).unwrap(),
            input_message_id: MessageId::from_uuid(Uuid::from_u128(95_912)).unwrap(),
            ..denied
        })
        .await
        .unwrap();
    assert!(matches!(
        denied_replay,
        navigator_store_api::Mutation::Replayed(AuthorizedChildOutcome::Denied)
    ));
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| matches!(value, AuthorizedChildOutcome::Denied))
            .count(),
        1
    );
    let children = fixture
        .store
        .load_direct_children(scope.root)
        .await
        .unwrap();
    assert_eq!(children.len(), 1);
    assert_eq!(
        fixture
            .store
            .load_authority_policy(children[0].participant_id)
            .await
            .unwrap()
            .participant_id,
        children[0].participant_id
    );
    assert!(
        fixture
            .store
            .load_grant(grant_id)
            .await
            .unwrap()
            .consumed_at
            .is_some()
    );
    let events = fixture
        .store
        .read_events(navigator_store_api::ReadEvents {
            session_id: scope.session_id,
            consumer: ConsumerKey::new("topology-95000").unwrap(),
            after: None,
            limit: navigator_store_api::EventReadLimit::new(100).unwrap(),
        })
        .await
        .unwrap();
    assert_eq!(
        events
            .events
            .iter()
            .filter(|event| event.event_type().as_str() == "authority.allowed")
            .count(),
        5
    );
    assert_eq!(
        events
            .events
            .iter()
            .filter(|event| event.event_type().as_str() == "authority.denied")
            .count(),
        3
    );
}

#[tokio::test]
async fn mailbox_snapshot_blob_cannot_forge_indexed_identity_or_state() {
    let mut fixture = SqliteFixture::new().await;
    assert_mailbox_store_contract(&mut fixture)
        .await
        .expect("establish mailbox facts");
    let message_id = MessageId::from_uuid(Uuid::from_u128(21)).unwrap();
    let bytes: Vec<u8> = sqlx::query_scalar("SELECT snapshot FROM messages WHERE message_id = ?")
        .bind(message_id.to_string())
        .fetch_one(fixture.store.pool())
        .await
        .unwrap();
    let mut forged: MessageSnapshot = serde_json::from_slice(&bytes).unwrap();
    forged.session_id = SessionId::from_uuid(Uuid::from_u128(999_999)).unwrap();
    sqlx::query("UPDATE messages SET snapshot = ? WHERE message_id = ?")
        .bind(serde_json::to_vec(&forged).unwrap())
        .bind(message_id.to_string())
        .execute(fixture.store.pool())
        .await
        .unwrap();
    assert_eq!(
        fixture.store.load_message(message_id).await,
        Err(StoreError::Corrupt)
    );
}

#[tokio::test]
async fn absent_operation_entities_have_typed_identity_bearing_failures() {
    let fixture = SqliteFixture::new().await;
    let template_id = TemplateId::from_uuid(uuid::Uuid::from_u128(41)).expect("TemplateId");
    let participant_id =
        ParticipantId::from_uuid(uuid::Uuid::from_u128(42)).expect("ParticipantId");
    let session_id = SessionId::from_uuid(uuid::Uuid::from_u128(43)).expect("SessionId");
    let operation_id = OperationId::from_uuid(uuid::Uuid::from_u128(44)).expect("OperationId");
    assert_eq!(
        fixture.store.load_template(template_id).await,
        Err(StoreError::TemplateNotFound { template_id })
    );
    assert_eq!(
        fixture.store.load_participant(participant_id).await,
        Err(StoreError::ParticipantNotFound { participant_id })
    );
    assert_eq!(
        fixture.store.load_root_participant(session_id).await,
        Err(StoreError::RootParticipantNotFound { session_id })
    );
    assert_eq!(
        fixture.store.load_operation(operation_id).await,
        Err(StoreError::OperationNotFound { operation_id })
    );
}

#[tokio::test]
async fn corrupted_operation_truth_is_rejected_independently_of_the_ledger() {
    let mut fixture = SqliteFixture::new().await;
    assert_operation_store_contract(&mut fixture)
        .await
        .expect("establish semantic Operation facts");
    let operation_id = uuid::Uuid::from_u128(810).to_string();

    sqlx::query(
        "UPDATE operations SET updated_at_seconds = created_at_seconds - 1 WHERE operation_id = ?",
    )
    .bind(&operation_id)
    .execute(fixture.store.pool())
    .await
    .expect("inject timestamp regression");
    assert_eq!(
        fixture
            .store
            .load_operation(
                OperationId::from_uuid(uuid::Uuid::from_u128(810)).expect("OperationId")
            )
            .await,
        Err(StoreError::Corrupt),
        "a regressed durable timestamp was exposed as trusted truth"
    );

    sqlx::query("UPDATE operations SET updated_at_seconds = created_at_seconds, state = 'failed' WHERE operation_id = ?")
        .bind(&operation_id)
        .execute(fixture.store.pool())
        .await
        .expect("inject outcome/state mismatch");
    assert_eq!(
        fixture
            .store
            .load_operation(
                OperationId::from_uuid(uuid::Uuid::from_u128(810)).expect("OperationId")
            )
            .await,
        Err(StoreError::Corrupt),
        "a success payload was accepted as a failed terminal outcome"
    );
}

#[tokio::test]
async fn operation_input_payload_and_digest_corruption_fail_closed_before_delivery() {
    let mut fixture = SqliteFixture::new().await;
    assert_operation_store_contract(&mut fixture)
        .await
        .expect("establish semantic Operation facts");
    let operation = OperationId::from_uuid(uuid::Uuid::from_u128(810)).expect("OperationId");
    let operation_text = operation.to_string();
    sqlx::query("UPDATE operations SET input_payload = ? WHERE operation_id = ?")
        .bind(br#"{"changed":false}"#.as_slice())
        .bind(&operation_text)
        .execute(fixture.store.pool())
        .await
        .expect("inject payload corruption");
    assert_eq!(
        fixture.store.load_operation_input(operation).await,
        Err(StoreError::Corrupt)
    );

    sqlx::query("UPDATE operations SET input_payload = ?, input_digest = zeroblob(32) WHERE operation_id = ?")
        .bind(br#"{"changed":true,"other":false}"#.as_slice())
        .bind(&operation_text)
        .execute(fixture.store.pool())
        .await
        .expect("inject digest corruption");
    assert_eq!(
        fixture.store.load_operation_input(operation).await,
        Err(StoreError::Corrupt)
    );
}

#[tokio::test]
async fn corrupted_template_registration_never_becomes_trusted_configuration() {
    let mut fixture = SqliteFixture::new().await;
    assert_operation_store_contract(&mut fixture)
        .await
        .expect("establish registered Template");
    let template = TemplateId::from_uuid(uuid::Uuid::from_u128(802)).expect("TemplateId");
    let serialized: Vec<u8> =
        sqlx::query_scalar("SELECT registration FROM templates WHERE template_id = ?")
            .bind(template.to_string())
            .fetch_one(fixture.store.pool())
            .await
            .expect("read independent registration bytes");
    assert!(
        !serialized
            .windows(b"secret-value-sentinel".len())
            .any(|window| window == b"secret-value-sentinel"),
        "persisted public Template contained a secret value"
    );
    sqlx::query("UPDATE templates SET registration = ? WHERE template_id = ?")
        .bind(br#"{"identity":"forged"}"#.as_slice())
        .bind(template.to_string())
        .execute(fixture.store.pool())
        .await
        .expect("inject malformed registration");
    assert_eq!(
        fixture.store.load_template(template).await,
        Err(StoreError::Corrupt)
    );
}

#[tokio::test]
async fn forged_participant_template_binding_fails_closed() {
    let mut fixture = SqliteFixture::new().await;
    assert_operation_store_contract(&mut fixture)
        .await
        .expect("establish root Participant");
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(800)).expect("SessionId");
    sqlx::query(
        "UPDATE participants SET template_compatibility = zeroblob(32) WHERE session_id = ?",
    )
    .bind(session.to_string())
    .execute(fixture.store.pool())
    .await
    .expect("inject forged Template binding");
    assert_eq!(
        fixture.store.load_root_participant(session).await,
        Err(StoreError::Corrupt),
        "a forged trusted Template binding was exposed as a Participant"
    );
    let operation = OperationId::from_uuid(uuid::Uuid::from_u128(810)).expect("OperationId");
    assert_eq!(
        fixture.store.load_operation_input(operation).await,
        Err(StoreError::Corrupt),
        "input remained deliverable through a forged Participant binding"
    );
}
