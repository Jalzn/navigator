#![cfg(unix)]

use std::process::Command;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ffi::OsString,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use navigator_consumer_protocol::v1 as consumer;
use navigator_core::{
    AcceptanceObservation, AuthenticatedHierarchyCaller, DeliveryContextFactory,
    DeliveryDriverError, DeliveryLoop, DeliveryPhase, DeliveryStep, FirstOperationConfig,
    FirstOperationService, MailboxDriver, OperationExecutor, OwnershipConfig, OwnershipSupervisor,
    ReleaseCommandError, ReleaseCommandFactory, RenewalCommandError, RenewalCommandFactory,
    WallClock,
};
use navigator_domain::{
    AuthorityProfile, BoundedText, Capability, ConsumerKey, ControlMessageKind, DeliveryAttemptId,
    DriverCapabilityRequirement, DriverId, DriverRequirement, FeedbackKind, HostId, InputSchema,
    LaunchAttemptId, MessageId, MessageKind, MonotonicInstant, OperationAction, OperationId,
    OperationState, ParticipantId, RequestId, ResourceBounds, ResourceScope, ScopedCapability,
    SessionId, Template, TemplateId, TrustedConfiguration, ValidatedMessageEnvelope,
};
use navigator_driver_protocol::v1 as driver;
use navigator_local::{BootstrapCredential, LocalClient, LocalNavigator, ServerConfig, serve};
use navigator_local::{
    DriverTransitionContexts, HierarchyCommandSink, LocalHierarchySink,
    MailboxBackedOperationExecutor, MailboxFirstOperationScheduler, SupervisedDriverConfig,
    SupervisedDriverExecutor, SupervisedMailboxWorker, TrustedToolCatalog,
    resolved_launch_attempt_for_config,
};
use navigator_store_api::{
    AcquireOwnership, AuthorityPolicySnapshot, AuthorityStore, AuthorityTemplatePolicy,
    CreateRootParticipant, EnqueueMessage, EventReadLimit, InstanceStore, LeaseDuration,
    MailboxStore, MessageCorrelation, OpenSession, OperationStore, OperationTerminalOutcome,
    PutAuthorityPolicy, ReadEvents, RegisterAuthorityTemplatePolicy, ReleaseOwnership,
    RenewOwnership, RequestContext, SessionStore, StartOperation, TransitionOperation,
};
use navigator_store_sqlite::SqliteStore;
use navigator_supervisor::{
    CredentialSource, InstanceSupervisor, OwnershipChannel, ProcessIoMode, SupervisorConfig,
    SupervisorError, UnixProcessBackend,
};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

const HOST: u128 = 10;
const SESSION: u128 = 11;
const PARTICIPANT: u128 = 12;
const TEMPLATE: u128 = 13;
const CREDENTIAL: [u8; 32] = [0x5a; 32];
static PROCESS_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct FixtureDirectory {
    temporary: tempfile::TempDir,
    persistent: Option<PathBuf>,
}

impl FixtureDirectory {
    fn new(prefix: &str) -> Self {
        let temporary = tempfile::Builder::new()
            .prefix(prefix)
            .tempdir_in("/tmp")
            .unwrap();
        let persistent = std::env::var_os("NAVIGATOR_DRIVER_FAULT_ROOT").map(PathBuf::from);
        if let Some(path) = &persistent {
            std::fs::create_dir_all(path).unwrap();
        }
        Self {
            temporary,
            persistent,
        }
    }

    fn path(&self) -> &std::path::Path {
        self.persistent
            .as_deref()
            .unwrap_or_else(|| self.temporary.path())
    }
}

#[derive(Default)]
struct ShutdownRecorder(Mutex<Vec<(u32, Vec<navigator_local::ShutdownAttemptEvidence>)>>);

impl navigator_local::ShutdownObserver for ShutdownRecorder {
    fn level_completed(&self, depth: u32, attempts: &[navigator_local::ShutdownAttemptEvidence]) {
        self.0.lock().unwrap().push((depth, attempts.to_vec()));
    }
}

fn fake_offered_capabilities() -> Vec<DriverCapabilityRequirement> {
    navigator_driver_fake::DEFAULT_CAPABILITY_IDS
        .into_iter()
        .map(|id| DriverCapabilityRequirement::new(Capability::new(id).unwrap(), 1, []).unwrap())
        .collect()
}

fn identity<T>(
    value: u128,
    make: impl FnOnce(Uuid) -> Result<T, navigator_domain::InvalidIdentity>,
) -> T {
    make(Uuid::from_u128(value)).unwrap()
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "three process hierarchy semantic oracle"
)]
async fn authenticated_three_level_hierarchy_routes_question_feedback_and_outcomes() {
    let _process_guard = PROCESS_TEST_LOCK.lock().await;
    let directory = tempfile::Builder::new()
        .prefix("nav-hierarchy-")
        .tempdir_in("/tmp")
        .unwrap();
    let store = Arc::new(
        SqliteStore::open(directory.path().join("state.db"))
            .await
            .unwrap(),
    );
    let host = identity(70_001, HostId::from_uuid);
    let session = identity(70_002, SessionId::from_uuid);
    let root = identity(70_003, ParticipantId::from_uuid);
    let root_operation = identity(70_004, OperationId::from_uuid);
    let root_message = identity(70_005, MessageId::from_uuid);
    let child_request = identity(70_010, RequestId::from_uuid);
    let grand_request = identity(70_011, RequestId::from_uuid);
    let feedback_request = identity(70_012, RequestId::from_uuid);
    let child = hierarchy_participant(child_request);
    let child_operation = hierarchy_operation(child_request);
    let grand = hierarchy_participant(grand_request);
    let grand_operation = hierarchy_operation(grand_request);
    let registered = template(fake_driver_id()).registration_snapshot();
    store
        .open_session(OpenSession::new(
            RequestContext::new(identity(70_020, RequestId::from_uuid), host),
            session,
            ConsumerKey::new("hierarchy-e2e").unwrap(),
            registered.compatibility,
        ))
        .await
        .unwrap();
    let lease = store
        .acquire_ownership(AcquireOwnership::new(
            RequestContext::new(identity(70_021, RequestId::from_uuid), host),
            session,
            LeaseDuration::from_millis(60_000).unwrap(),
        ))
        .await
        .unwrap()
        .value()
        .clone();
    store.register_template(registered.clone()).await.unwrap();
    store
        .create_root_participant(CreateRootParticipant {
            context: RequestContext::new(identity(70_022, RequestId::from_uuid), host),
            session_id: session,
            epoch: lease.epoch(),
            participant_id: root,
            template_id: registered.identity,
            expected_compatibility: registered.compatibility,
        })
        .await
        .unwrap();
    let mut rules = Vec::new();
    for participant in [root, child] {
        rules.push(ScopedCapability::new(
            Capability::new("participant.spawn").unwrap(),
            ResourceScope::Participant(participant),
        ));
    }
    for operation in [root_operation, child_operation, grand_operation] {
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
    for participant in [root, child, grand] {
        rules.push(ScopedCapability::new(
            Capability::new("message.send").unwrap(),
            ResourceScope::Participant(participant),
        ));
        rules.push(ScopedCapability::new(
            Capability::new("participant.status").unwrap(),
            ResourceScope::Participant(participant),
        ));
    }
    let full = AuthorityProfile::new(rules.clone(), rules).unwrap();
    store
        .put_authority_policy(PutAuthorityPolicy {
            context: RequestContext::new(identity(70_023, RequestId::from_uuid), host),
            session_id: session,
            epoch: lease.epoch(),
            policy: AuthorityPolicySnapshot {
                session_id: session,
                participant_id: root,
                session: full.clone(),
                parent: full.clone(),
                template: full.clone(),
                relationship: full.clone(),
                subject: full.clone(),
            },
        })
        .await
        .unwrap();
    store
        .register_authority_template_policy(RegisterAuthorityTemplatePolicy {
            context: RequestContext::new(identity(70_024, RequestId::from_uuid), host),
            session_id: session,
            epoch: lease.epoch(),
            policy: AuthorityTemplatePolicy {
                template_id: registered.identity,
                allowed_parent_templates: [registered.identity].into_iter().collect(),
                template: full.clone(),
                relationship: full.clone(),
                subject: full,
            },
        })
        .await
        .unwrap();
    let scenario_dir = directory.path().join("scenarios");
    let journal_dir = directory.path().join("journals");
    std::fs::create_dir(&scenario_dir).unwrap();
    std::fs::create_dir(&journal_dir).unwrap();
    let question_event_id = {
        let digest = Sha256::new()
            .chain_update(b"navigator.fake.event\0")
            .chain_update(1_u64.to_be_bytes())
            .finalize();
        let mut bytes: [u8; 16] = digest[..16].try_into().unwrap();
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        bytes
    };
    let question_id = hierarchy_message_from_bytes(&question_event_id);
    let feedback = serde_json::to_string(&ValidatedMessageEnvelope::correlated_feedback(
        grand_operation,
        question_id,
        FeedbackKind::Acknowledged,
    ))
    .unwrap();
    let marker = directory.path().join("question-committed");
    let grand_outcome_marker = directory.path().join("grand-outcome-committed");
    let child_outcome_marker = directory.path().join("child-outcome-committed");
    let root_scenario = serde_json::json!({"events":[
        {"kind":"spawn_child","request_id":child_request.to_string(),"template_id":registered.identity.to_string(),"task_input":"{}"},
        {"kind":"outcome","operation_id":root_operation.to_string(),"message_id":root_message.to_string(),"outcome":"succeeded","wait_for_file":child_outcome_marker.to_string_lossy()}
    ]});
    let child_scenario = serde_json::json!({"events":[
        {"kind":"spawn_child","request_id":grand_request.to_string(),"template_id":registered.identity.to_string(),"task_input":"{}"},
        {"kind":"send","request_id":feedback_request.to_string(),"destination_participant_id":grand.to_string(),"validated_envelope":feedback,"wait_for_file":marker.to_string_lossy()},
        {"kind":"outcome","operation_id":child_operation.to_string(),"message_id":hierarchy_message_from_bytes(child_request.as_uuid().as_bytes()).to_string(),"outcome":"succeeded","wait_for_file":grand_outcome_marker.to_string_lossy()}
    ]});
    let grand_message = hierarchy_message_from_bytes(grand_request.as_uuid().as_bytes());
    let grand_scenario = serde_json::json!({"events":[
        {"kind":"question","operation_id":grand_operation.to_string(),"message_id":grand_message.to_string(),"code":"input.required"},
        {"kind":"outcome","operation_id":grand_operation.to_string(),"message_id":grand_message.to_string(),"outcome":"succeeded"}
    ]});
    let control_root = tempfile::Builder::new()
        .prefix("nav-h3")
        .tempdir_in("/tmp")
        .unwrap();
    std::fs::set_permissions(
        control_root.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let backend =
        Arc::new(UnixProcessBackend::new(control_root.path().join("credentials")).unwrap());
    let supervisor = Arc::new(InstanceSupervisor::new(
        store.clone(),
        backend,
        Credentials,
        SupervisorConfig {
            graceful_timeout: Duration::from_millis(500),
            forced_timeout: Duration::from_millis(500),
            ownership_loss_timeout: Duration::from_millis(500),
        },
    ));
    let mut environment = BTreeMap::new();
    environment.insert(
        OsString::from("NAVIGATOR_FAKE_DRIVER_SCENARIO_FILE"),
        scenario_dir.clone().into_os_string(),
    );
    environment.insert(
        OsString::from("NAVIGATOR_FAKE_DRIVER_JOURNAL_FILE"),
        journal_dir.clone().into_os_string(),
    );
    let allowlist = environment
        .keys()
        .cloned()
        .chain([OsString::from("NAVIGATOR_CONTROL_SOCKET")])
        .collect();
    let driver_config = SupervisedDriverConfig {
        bootstrap_configuration: Vec::new(),
        trusted_artifacts: Vec::new(),
        ownership_channel: OwnershipChannel::Stdin,
        process_io_mode: ProcessIoMode::Headless,
        driver_id: fake_driver_id(),
        program: fake_binary(),
        expected_executable_identity: executable_digest(),
        arguments: vec![],
        working_directory: directory.path().to_path_buf(),
        environment,
        environment_allowlist: allowlist,
        control_directory: control_root.path().to_path_buf(),
        control_socket_environment: OsString::from("NAVIGATOR_CONTROL_SOCKET"),
        connect_timeout: if std::env::var_os("NAVIGATOR_EXTERNAL_FAULT_POINT").is_some() {
            Duration::from_secs(30)
        } else {
            Duration::from_secs(2)
        },
        offered_capabilities: fake_offered_capabilities(),
    };
    let empty_catalog = TrustedToolCatalog::new(serde_json::json!([])).unwrap();
    let launch_attempt = |participant| {
        resolved_launch_attempt_for_config(
            participant,
            lease.epoch(),
            &driver_config,
            &empty_catalog,
        )
        .unwrap()
    };
    for (participant, scenario) in [
        (root, root_scenario),
        (child, child_scenario),
        (grand, grand_scenario),
    ] {
        let attempt = launch_attempt(participant);
        std::fs::write(
            scenario_dir.join(format!("{attempt}.scenario.json")),
            serde_json::to_vec(&scenario).unwrap(),
        )
        .unwrap();
    }
    let shutdown_recorder = Arc::new(ShutdownRecorder::default());
    let executor = Arc::new(
        SupervisedDriverExecutor::new(store.clone(), supervisor, host, driver_config.clone())
            .with_shutdown_observer(shutdown_recorder.clone()),
    );
    let commands = Arc::new(Commands(AtomicU64::new(0)));
    let ownership = OwnershipSupervisor::start(
        store.clone(),
        Arc::new(Clock),
        commands.clone(),
        commands,
        lease.clone(),
        OwnershipConfig {
            lease_duration: LeaseDuration::from_millis(60_000).unwrap(),
            renewal_period: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(1),
        },
    )
    .unwrap();
    let operation_executor = Arc::new(
        MailboxBackedOperationExecutor::new(
            store.clone(),
            executor.clone(),
            host,
            Duration::from_secs(2),
            Duration::from_millis(20),
            Duration::from_secs(1),
            Duration::from_secs(5),
            64,
        )
        .unwrap(),
    );
    let service = Arc::new(FirstOperationService::new(
        store.clone(),
        operation_executor.clone(),
        Arc::new(DriverTransitionContexts { host_id: host }),
        3,
        FirstOperationConfig {
            capacity_wait: Duration::from_secs(1),
            // This real-process scenario performs two sequential descendant
            // launches before the root can emit its terminal report. The
            // absolute report deadline remains finite, but must cover that
            // intentionally serialized depth under loaded gate execution.
            report_deadline: Duration::from_secs(10),
        },
    ));
    let scheduler = Arc::new(MailboxFirstOperationScheduler::new(
        service.clone(),
        operation_executor.clone(),
        ownership.admission(),
    ));
    let sink = Arc::new(LocalHierarchySink::new(store.clone(), host).with_scheduler(scheduler));
    executor.install_hierarchy_sink(sink.clone()).unwrap();
    let marker_store = store.clone();
    let marker_path = marker.clone();
    tokio::spawn(async move {
        loop {
            if marker_store
                .load_operation(grand_operation)
                .await
                .is_ok_and(|value| value.state == OperationState::Waiting)
            {
                std::fs::write(&marker_path, b"committed").unwrap();
                break;
            }
            tokio::task::yield_now().await;
        }
    });
    let child_outcome_store = store.clone();
    let child_outcome_path = child_outcome_marker.clone();
    tokio::spawn(async move {
        loop {
            if child_outcome_store
                .load_mailbox(root)
                .await
                .is_ok_and(|mailbox| {
                    mailbox.iter().any(|message| {
                        message.source == child
                            && matches!(
                                message.envelope.body(),
                                navigator_domain::MessageBody::OperationOutcome {
                                    operation_id,
                                    ..
                                } if *operation_id == child_operation
                            )
                    })
                })
            {
                std::fs::write(&child_outcome_path, b"committed").unwrap();
                break;
            }
            tokio::task::yield_now().await;
        }
    });
    let outcome_marker_store = store.clone();
    let outcome_marker_path = grand_outcome_marker.clone();
    tokio::spawn(async move {
        loop {
            if outcome_marker_store
                .load_mailbox(child)
                .await
                .is_ok_and(|mailbox| {
                    mailbox.iter().any(|message| {
                        message.source == grand
                            && matches!(
                                message.envelope.body(),
                                navigator_domain::MessageBody::OperationOutcome {
                                    operation_id,
                                    ..
                                } if *operation_id == grand_operation
                            )
                    })
                })
            {
                std::fs::write(&outcome_marker_path, b"committed").unwrap();
                break;
            }
            tokio::task::yield_now().await;
        }
    });
    let handle = service
        .start(
            ownership.admission().admit().unwrap(),
            StartOperation {
                context: RequestContext::new(identity(70_025, RequestId::from_uuid), host),
                session_id: session,
                epoch: lease.epoch(),
                operation_id: root_operation,
                participant_id: root,
                input_message_id: root_message,
                input: template(fake_driver_id()).validate_input(b"{}").unwrap(),
            },
        )
        .await
        .unwrap();
    drop(handle);
    let completed = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let root_done = store.load_operation(root_operation).await;
            let child_done = store.load_operation(child_operation).await;
            let grand_done = store.load_operation(grand_operation).await;
            if [root_done, child_done, grand_done]
                .into_iter()
                .all(|value| {
                    value.is_ok_and(|snapshot| snapshot.state == OperationState::Succeeded)
                })
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        completed.is_ok(),
        "hierarchy did not settle: root={:?} child={:?} grand={:?} journals={:?}",
        store.load_operation(root_operation).await,
        store.load_operation(child_operation).await,
        store.load_operation(grand_operation).await,
        journal_snapshot(&journal_dir),
    );
    let root_children = store.load_direct_children(root).await.unwrap();
    let child_children = store.load_direct_children(child).await.unwrap();
    assert_eq!(root_children.len(), 1);
    assert_eq!(root_children[0].participant_id, child);
    assert_eq!(child_children.len(), 1);
    assert_eq!(child_children[0].participant_id, grand);
    assert!(store.load_direct_children(grand).await.unwrap().is_empty());
    assert!(
        matches!(store.load_message(question_id).await.unwrap().envelope.body(), navigator_domain::MessageBody::Question { operation_id, .. } if *operation_id == grand_operation)
    );
    let feedback_id = hierarchy_message_from_bytes(feedback_request.as_uuid().as_bytes());
    let feedback_snapshot = store.load_message(feedback_id).await.unwrap();
    assert!(matches!(
        feedback_snapshot.envelope.body(),
        navigator_domain::MessageBody::CorrelatedFeedback {
            operation_id,
            in_reply_to,
            feedback: FeedbackKind::Acknowledged,
        } if *operation_id == grand_operation && *in_reply_to == question_id
    ));
    assert!(matches!(
        feedback_snapshot.state,
        navigator_store_api::MessageDeliveryState::Accepted { .. }
    ));
    let child_mailbox = store.load_mailbox(child).await.unwrap();
    assert!(child_mailbox.iter().any(|message| {
        message.source == grand
            && matches!(
                message.envelope.body(),
                navigator_domain::MessageBody::OperationOutcome { operation_id, .. }
                    if *operation_id == grand_operation
            )
    }));
    let root_mailbox = store.load_mailbox(root).await.unwrap();
    assert!(root_mailbox.iter().any(|message| {
        message.source == child
            && matches!(
                message.envelope.body(),
                navigator_domain::MessageBody::OperationOutcome { operation_id, .. }
                    if *operation_id == child_operation
            )
    }));

    let expected_journals = [(root, 2_u64, 1_usize), (child, 3, 2), (grand, 2, 0)]
        .into_iter()
        .map(|(participant, sequence, hierarchy_results)| {
            (
                launch_attempt(participant),
                participant,
                sequence,
                hierarchy_results,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        expected_journals
            .iter()
            .map(|(attempt, _, _, _)| *attempt)
            .collect::<BTreeSet<_>>()
            .len(),
        3,
        "each Participant must have a distinct launch attempt"
    );
    let journal_entries = journal_snapshot(&journal_dir);
    assert_eq!(journal_entries.len(), 3);
    for (attempt, participant, sequence, hierarchy_results) in expected_journals {
        let expected_name = OsString::from(format!("{attempt}.journal.json"));
        let (_, bytes) = journal_entries
            .iter()
            .find(|(name, _)| name == &expected_name)
            .unwrap_or_else(|| panic!("missing journal for launch attempt {attempt}"));
        let journal: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        let binding = journal.get("binding").unwrap();
        assert_eq!(
            json_identity(binding, "participant_id"),
            participant.as_uuid()
        );
        assert_eq!(
            json_identity(binding, "launch_attempt_id"),
            attempt.as_uuid()
        );
        assert!(
            journal["next_event_sequence"]
                .as_u64()
                .is_some_and(|value| value >= sequence)
        );
        assert_eq!(journal["scripted_event_index"].as_u64(), Some(sequence - 1));
        assert_eq!(
            journal["hierarchy_results"].as_object().unwrap().len(),
            hierarchy_results
        );
    }

    let events = store
        .read_events(ReadEvents {
            session_id: session,
            consumer: ConsumerKey::new("hierarchy-e2e").unwrap(),
            after: None,
            limit: EventReadLimit::new(64).unwrap(),
        })
        .await
        .unwrap();
    let event_types = events
        .events
        .iter()
        .map(|event| event.event_type().as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        event_types
            .iter()
            .filter(|event_type| **event_type == "participant.created")
            .count(),
        3
    );
    assert_eq!(
        event_types
            .iter()
            .filter(|event_type| **event_type == "operation.succeeded")
            .count(),
        3
    );
    assert_eq!(
        event_types
            .iter()
            .filter(|event_type| **event_type == "authority.allowed")
            .count(),
        6
    );
    let accepted_position = events
        .events
        .iter()
        .find(|event| {
            event.event_type().as_str() == "message.accepted"
                && serde_json::from_slice::<serde_json::Value>(event.data().as_slice())
                    .is_ok_and(|data| data["message_id"] == feedback_id.to_string())
        })
        .expect("feedback acceptance Event missing")
        .position();
    let resumed_position = events
        .events
        .iter()
        .find(|event| {
            event.event_type().as_str() == "operation.resumed"
                && serde_json::from_slice::<serde_json::Value>(event.data().as_slice())
                    .is_ok_and(|data| data["operation_id"] == grand_operation.to_string())
        })
        .expect("feedback resume Event missing")
        .position();
    assert!(
        accepted_position < resumed_position,
        "operation resumed before its correlated feedback was durably accepted"
    );
    let shutdown = executor.shutdown().await;
    if let Err(error) = shutdown {
        let mut launches = Vec::new();
        for participant in [root, child, grand] {
            launches.push(store.load_launch(launch_attempt(participant)).await);
        }
        panic!(
            "hierarchy shutdown failed: {error:?}; completed_levels={:?}; launches={launches:?}",
            shutdown_recorder.0.lock().unwrap()
        );
    }
    assert_stopped_caller_cannot_issue_hierarchy_commands(
        &store,
        &sink,
        AuthenticatedHierarchyCaller {
            host_id: host,
            session_id: session,
            participant_id: root,
            launch_attempt_id: launch_attempt(root),
            instance_id: store
                .load_launch(launch_attempt(root))
                .await
                .unwrap()
                .instance_id
                .unwrap(),
            ownership_epoch: lease.epoch(),
        },
        child,
        child_operation,
    )
    .await;
    let _ = ownership.shutdown().await;
}

async fn assert_stopped_caller_cannot_issue_hierarchy_commands(
    store: &SqliteStore,
    sink: &LocalHierarchySink<SqliteStore>,
    caller: AuthenticatedHierarchyCaller,
    child: ParticipantId,
    child_operation: OperationId,
) {
    assert_eq!(
        store
            .load_launch(caller.launch_attempt_id)
            .await
            .unwrap()
            .state,
        navigator_store_api::LaunchState::Stopped
    );
    let mailbox_before = store.load_mailbox(child).await.unwrap();
    let status = driver::HierarchyCommand {
        request_id: request(70_030).as_uuid().as_bytes().to_vec(),
        command: Some(driver::hierarchy_command::Command::Status(
            driver::ParticipantStatusCommand {
                participant_id: child.as_uuid().as_bytes().to_vec(),
                operation_id: child_operation.as_uuid().as_bytes().to_vec(),
            },
        )),
    };
    assert!(sink.handle(caller, status).await.is_err());
    let envelope = ValidatedMessageEnvelope::control(child_operation, ControlMessageKind::Reminder);
    let send = driver::HierarchyCommand {
        request_id: request(70_031).as_uuid().as_bytes().to_vec(),
        command: Some(driver::hierarchy_command::Command::Send(
            driver::SendMessageCommand {
                destination_participant_id: child.as_uuid().as_bytes().to_vec(),
                validated_envelope: serde_json::to_vec(&envelope).unwrap(),
            },
        )),
    };
    assert!(sink.handle(caller, send).await.is_err());
    let cancel = driver::HierarchyCommand {
        request_id: request(70_032).as_uuid().as_bytes().to_vec(),
        command: Some(driver::hierarchy_command::Command::Cancel(
            driver::CancelHierarchyCommand {
                participant_id: child.as_uuid().as_bytes().to_vec(),
                operation_id: child_operation.as_uuid().as_bytes().to_vec(),
            },
        )),
    };
    assert!(sink.handle(caller, cancel).await.is_err());
    assert_eq!(store.load_mailbox(child).await.unwrap(), mailbox_before);
}

fn json_identity(object: &serde_json::Value, field: &str) -> Uuid {
    let bytes = object[field]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| u8::try_from(value.as_u64().unwrap()).unwrap())
        .collect::<Vec<_>>();
    Uuid::from_slice(&bytes).unwrap()
}

fn request(value: u128) -> RequestId {
    identity(value, RequestId::from_uuid)
}

fn context(value: u128) -> RequestContext {
    RequestContext::new(request(value), identity(HOST, HostId::from_uuid))
}

struct Clock;
impl WallClock for Clock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

#[derive(Debug)]
struct StoreClock(std::sync::atomic::AtomicI64);
impl StoreClock {
    fn new(seconds: i64) -> Self {
        Self(std::sync::atomic::AtomicI64::new(seconds))
    }
    fn set(&self, seconds: i64) {
        self.0.store(seconds, Ordering::SeqCst);
    }
}
impl navigator_domain::Clock for StoreClock {
    fn wall_now(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::SeqCst)).unwrap()
    }
    fn monotonic_now(&self) -> MonotonicInstant {
        MonotonicInstant::from_ticks(u64::try_from(self.0.load(Ordering::SeqCst)).unwrap())
    }
}
impl WallClock for StoreClock {
    fn now(&self) -> OffsetDateTime {
        navigator_domain::Clock::wall_now(self)
    }
}

struct Commands(AtomicU64);
impl Commands {
    fn next(&self) -> RequestId {
        request(1_000 + u128::from(self.0.fetch_add(1, Ordering::Relaxed)))
    }
}
impl RenewalCommandFactory for Commands {
    fn create(
        &self,
        lease: &navigator_store_api::OwnershipLease,
        duration: LeaseDuration,
    ) -> Result<RenewOwnership, RenewalCommandError> {
        Ok(RenewOwnership::new(
            context(self.next().as_uuid().as_u128()),
            lease.session_id(),
            lease.epoch(),
            duration,
        ))
    }
}
impl ReleaseCommandFactory for Commands {
    fn create(
        &self,
        lease: &navigator_store_api::OwnershipLease,
    ) -> Result<ReleaseOwnership, ReleaseCommandError> {
        Ok(ReleaseOwnership::new(
            context(self.next().as_uuid().as_u128()),
            lease.session_id(),
            lease.epoch(),
        ))
    }
}

struct Credentials;
impl CredentialSource for Credentials {
    fn next_credential(&mut self) -> Result<Vec<u8>, SupervisorError> {
        Ok(CREDENTIAL.to_vec())
    }
}

fn fake_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_navigator-driver-fake"))
}

fn executable_digest() -> [u8; 32] {
    Sha256::digest(std::fs::read(fake_binary()).unwrap()).into()
}

fn template(driver_id: DriverId) -> Template {
    Template::register(
        identity(TEMPLATE, TemplateId::from_uuid),
        BoundedText::new("root".to_owned()).unwrap(),
        DriverRequirement::new(driver_id, vec![]).unwrap(),
        TrustedConfiguration::new(BoundedText::new("e2e".to_owned()).unwrap(), []).unwrap(),
        ResourceBounds::new(1024, 1000, 1).unwrap(),
        InputSchema::new(vec![]).unwrap(),
    )
    .unwrap()
}

fn fake_driver_id() -> DriverId {
    let digest = Sha256::new()
        .chain_update(b"navigator.fake.driver\0")
        .chain_update(CREDENTIAL)
        .finalize();
    let mut bytes: [u8; 16] = digest[..16].try_into().unwrap();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    DriverId::from_uuid(Uuid::from_bytes(bytes)).unwrap()
}

fn hierarchy_identity<T>(
    domain: &[u8],
    request_id: RequestId,
    make: impl FnOnce(Uuid) -> Result<T, navigator_domain::InvalidIdentity>,
) -> T {
    let digest = Sha256::new()
        .chain_update(domain)
        .chain_update(request_id.as_uuid().as_bytes())
        .finalize();
    let mut bytes: [u8; 16] = digest[..16].try_into().unwrap();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    make(Uuid::from_bytes(bytes)).unwrap()
}

fn hierarchy_participant(request_id: RequestId) -> ParticipantId {
    hierarchy_identity(
        b"navigator.hierarchy.child.v1",
        request_id,
        ParticipantId::from_uuid,
    )
}

fn hierarchy_operation(request_id: RequestId) -> OperationId {
    hierarchy_identity(
        b"navigator.hierarchy.operation.v1",
        request_id,
        OperationId::from_uuid,
    )
}

fn hierarchy_message_from_bytes(bytes: &[u8]) -> MessageId {
    let digest = Sha256::new()
        .chain_update(b"navigator.hierarchy.message.v1")
        .chain_update(bytes)
        .finalize();
    let mut id: [u8; 16] = digest[..16].try_into().unwrap();
    id[6] = (id[6] & 0x0f) | 0x40;
    id[8] = (id[8] & 0x3f) | 0x80;
    MessageId::from_uuid(Uuid::from_bytes(id)).unwrap()
}

fn journal_snapshot(path: &std::path::Path) -> Vec<(OsString, Vec<u8>)> {
    if path.is_dir() {
        let mut entries = path
            .read_dir()
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), std::fs::read(entry.path()).unwrap())
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        entries
    } else {
        vec![(path.as_os_str().to_owned(), std::fs::read(path).unwrap())]
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the vertical oracle keeps process launch, durable transitions, events, and cleanup together"
)]
async fn run_case(kind: &str, terminal: OperationState, operation_value: u128) {
    let directory = FixtureDirectory::new("navigator-e2e-");
    let store = Arc::new(
        SqliteStore::open(directory.path().join("navigator.db"))
            .await
            .unwrap(),
    );
    let host = identity(HOST, HostId::from_uuid);
    let session = identity(SESSION, SessionId::from_uuid);
    let participant = identity(PARTICIPANT, ParticipantId::from_uuid);
    let operation = identity(operation_value, OperationId::from_uuid);
    let message = identity(operation_value + 1, MessageId::from_uuid);
    let trusted_driver = if kind == "catalog_mismatch" {
        identity(14, DriverId::from_uuid)
    } else {
        fake_driver_id()
    };
    let registered = template(trusted_driver).registration_snapshot();

    store
        .open_session(OpenSession::new(
            context(20),
            session,
            ConsumerKey::new("e2e").unwrap(),
            registered.compatibility,
        ))
        .await
        .unwrap();
    let lease = store
        .acquire_ownership(AcquireOwnership::new(
            context(21),
            session,
            LeaseDuration::from_millis(60_000).unwrap(),
        ))
        .await
        .unwrap()
        .value()
        .clone();
    store.register_template(registered.clone()).await.unwrap();
    store
        .create_root_participant(CreateRootParticipant {
            context: context(22),
            session_id: session,
            epoch: lease.epoch(),
            participant_id: participant,
            template_id: registered.identity,
            expected_compatibility: registered.compatibility,
        })
        .await
        .unwrap();
    let scenario_path = directory.path().join("scenario.json");
    let scenario = match kind {
        "success" | "stale_epoch" => format!(
            r#"{{"events":[{{"kind":"outcome","operation_id":"{operation}","message_id":"{message}","outcome":"succeeded"}}]}}"#
        ),
        "failure" => format!(
            r#"{{"events":[{{"kind":"outcome","operation_id":"{operation}","message_id":"{message}","outcome":"failed"}}]}}"#
        ),
        "forged_question" => format!(
            r#"{{"events":[{{"kind":"question","operation_id":"{operation}","message_id":"{message}","delivery_attempt_id":"{}","code":"input.required"}}]}}"#,
            Uuid::from_u128(operation_value + 2)
        ),
        "idle" | "catalog_mismatch" => r#"{"events":[]}"#.to_owned(),
        "hang" => r#"{"delivery_fault":"hang","events":[]}"#.to_owned(),
        _ => unreachable!(),
    };
    std::fs::write(&scenario_path, scenario).unwrap();

    let control_root = tempfile::Builder::new()
        .prefix("nav-e2e")
        .tempdir_in("/tmp")
        .unwrap();
    let control_dir = control_root.path().to_path_buf();
    std::fs::set_permissions(
        &control_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let backend = Arc::new(UnixProcessBackend::new(control_dir.join("credentials")).unwrap());
    let supervisor = Arc::new(InstanceSupervisor::new(
        store.clone(),
        backend.clone(),
        Credentials,
        SupervisorConfig {
            graceful_timeout: Duration::from_secs(1),
            forced_timeout: Duration::from_secs(1),
            ownership_loss_timeout: Duration::from_secs(2),
        },
    ));
    let mut environment = BTreeMap::new();
    environment.insert(
        OsString::from("NAVIGATOR_FAKE_DRIVER_SCENARIO_FILE"),
        scenario_path.into_os_string(),
    );
    let journal_path = if kind == "stale_epoch" {
        let path = directory.path().join("journals");
        std::fs::create_dir(&path).unwrap();
        path
    } else {
        directory.path().join("journal.json")
    };
    environment.insert(
        OsString::from("NAVIGATOR_FAKE_DRIVER_JOURNAL_FILE"),
        journal_path.clone().into_os_string(),
    );
    let allowlist = environment
        .keys()
        .cloned()
        .chain([OsString::from("NAVIGATOR_CONTROL_SOCKET")])
        .collect::<BTreeSet<_>>();
    let driver_config = SupervisedDriverConfig {
        bootstrap_configuration: Vec::new(),
        trusted_artifacts: Vec::new(),
        ownership_channel: OwnershipChannel::Stdin,
        process_io_mode: ProcessIoMode::Headless,
        driver_id: fake_driver_id(),
        program: fake_binary(),
        expected_executable_identity: executable_digest(),
        arguments: vec![],
        working_directory: directory.path().to_path_buf(),
        environment,
        environment_allowlist: allowlist,
        control_directory: control_dir.clone(),
        control_socket_environment: OsString::from("NAVIGATOR_CONTROL_SOCKET"),
        connect_timeout: if std::env::var_os("NAVIGATOR_EXTERNAL_FAULT_POINT").is_some() {
            Duration::from_secs(30)
        } else {
            Duration::from_secs(2)
        },
        offered_capabilities: fake_offered_capabilities(),
    };
    let launch_attempt = resolved_launch_attempt_for_config(
        participant,
        lease.epoch(),
        &driver_config,
        &TrustedToolCatalog::new(serde_json::json!([])).unwrap(),
    )
    .unwrap();
    let executor = Arc::new(SupervisedDriverExecutor::new(
        store.clone(),
        supervisor,
        host,
        driver_config,
    ));
    let commands = Arc::new(Commands(AtomicU64::new(0)));
    let ownership = OwnershipSupervisor::start(
        store.clone(),
        Arc::new(Clock),
        commands.clone(),
        commands,
        lease.clone(),
        OwnershipConfig {
            lease_duration: LeaseDuration::from_millis(60_000).unwrap(),
            renewal_period: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(1),
        },
    )
    .unwrap();
    let operation_executor = Arc::new(
        MailboxBackedOperationExecutor::new(
            store.clone(),
            Arc::clone(&executor),
            host,
            if kind == "hang" {
                Duration::from_millis(100)
            } else {
                Duration::from_secs(2)
            },
            Duration::from_millis(20),
            if kind == "hang" {
                Duration::from_millis(50)
            } else {
                Duration::from_secs(1)
            },
            if kind == "hang" {
                Duration::from_millis(200)
            } else {
                Duration::from_secs(5)
            },
            64,
        )
        .unwrap(),
    );
    let service = FirstOperationService::new(
        store.clone(),
        operation_executor.clone(),
        Arc::new(DriverTransitionContexts { host_id: host }),
        1,
        FirstOperationConfig {
            capacity_wait: Duration::from_secs(1),
            report_deadline: Duration::from_millis(100),
        },
    );
    let handle = service
        .start(
            ownership.admission().admit().unwrap(),
            StartOperation {
                context: context(30 + operation_value),
                session_id: session,
                epoch: lease.epoch(),
                operation_id: operation,
                participant_id: participant,
                input_message_id: message,
                input: template(trusted_driver).validate_input(b"{}").unwrap(),
            },
        )
        .await
        .unwrap();
    let admitted = handle.admitted().value().clone();
    drop(handle);
    assert_eq!(admitted.state, OperationState::Queued);

    let settled = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let current = store.load_operation(operation).await.unwrap();
            if current.state.is_terminal() {
                break current;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let snapshot = settled.unwrap_or_else(|_| {
        panic!(
            "{kind} did not become terminal; journal={:?}",
            std::fs::read_to_string(directory.path().join("journal.json"))
        )
    });
    if snapshot.state != terminal {
        eprintln!(
            "journal={:?}",
            std::fs::read_to_string(directory.path().join("journal.json"))
        );
    }
    assert_eq!(
        snapshot.state, terminal,
        "terminal outcome: {:?}",
        snapshot.terminal_outcome
    );
    if matches!(
        kind,
        "success" | "failure" | "idle" | "stale_epoch" | "forged_question"
    ) {
        assert!(matches!(
            store.load_message(message).await.unwrap().state,
            navigator_store_api::MessageDeliveryState::Accepted { .. }
        ));
    }
    if kind == "idle" {
        assert!(matches!(
            snapshot.terminal_outcome,
            Some(OperationTerminalOutcome::Failed { ref code, .. })
                if code.as_str() == "result_deadline"
        ));
    }
    if kind == "forged_question" {
        assert!(matches!(
            snapshot.terminal_outcome,
            Some(OperationTerminalOutcome::Uncertain { .. })
        ));
        assert!(
            store
                .load_mailbox(participant)
                .await
                .unwrap()
                .iter()
                .all(|message| !matches!(
                    message.envelope.body(),
                    navigator_domain::MessageBody::Question { .. }
                )),
            "a competing delivery attempt persisted a Question before causal validation"
        );
    }
    let events = store
        .read_events(ReadEvents {
            session_id: session,
            consumer: ConsumerKey::new("e2e").unwrap(),
            after: None,
            limit: EventReadLimit::new(64).unwrap(),
        })
        .await
        .unwrap();
    let operation_events = events
        .events
        .iter()
        .filter(|event| event.event_type().as_str().starts_with("operation."))
        .map(|event| event.event_type().as_str())
        .collect::<Vec<_>>();
    let final_event = match terminal {
        OperationState::Succeeded => "operation.succeeded",
        OperationState::Failed => "operation.failed",
        OperationState::Uncertain => "operation.uncertain",
        _ => unreachable!(),
    };
    let expected = if matches!(kind, "catalog_mismatch" | "hang") {
        vec!["operation.queued", "operation.starting", final_event]
    } else {
        vec![
            "operation.queued",
            "operation.starting",
            "operation.running",
            final_event,
        ]
    };
    assert_eq!(operation_events, expected);
    if kind == "catalog_mismatch" {
        assert!(
            !directory.path().join("journal.json").exists(),
            "trusted catalog mismatch spawned the Driver"
        );
    }

    if kind == "stale_epoch" {
        let stale = operation_executor.ensure_ready(&snapshot).await.unwrap();
        let stale_permit = ownership.admission().admit().unwrap();
        let before = journal_snapshot(&journal_path);
        store
            .release_ownership(ReleaseOwnership::new(
                context(operation_value + 800),
                session,
                lease.epoch(),
            ))
            .await
            .unwrap();
        let replacement = store
            .acquire_ownership(AcquireOwnership::new(
                context(operation_value + 801),
                session,
                LeaseDuration::from_millis(60_000).unwrap(),
            ))
            .await
            .unwrap()
            .value()
            .clone();
        assert!(
            OperationExecutor::deliver(
                operation_executor.as_ref(),
                &stale_permit,
                &stale,
                &snapshot,
                b"{}",
            )
            .await
            .is_err(),
            "stale authenticated Instance crossed the Driver boundary"
        );
        assert_eq!(
            journal_snapshot(&journal_path),
            before,
            "stale epoch produced a Driver effect"
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let has_material_entry = control_dir.read_dir().is_ok_and(|entries| {
                    entries.filter_map(Result::ok).any(|entry| {
                        entry.file_name() != "credentials"
                            || !entry.file_type().is_ok_and(|kind| kind.is_dir())
                            || entry
                                .path()
                                .read_dir()
                                .is_ok_and(|mut children| children.next().is_some())
                    })
                });
                if !has_material_entry {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("epoch N process retained its ownership channel");
        let current = operation_executor
            .ensure_ready(&snapshot)
            .await
            .expect("epoch N+1 must bind a fresh attempt-scoped Driver journal");
        assert_eq!(current.ownership_epoch(), replacement.epoch().get());
        store
            .release_ownership(ReleaseOwnership::new(
                context(operation_value + 802),
                session,
                replacement.epoch(),
            ))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let has_material_entry = control_dir.read_dir().is_ok_and(|entries| {
                    entries.filter_map(Result::ok).any(|entry| {
                        entry.file_name() != "credentials"
                            || !entry.file_type().is_ok_and(|kind| kind.is_dir())
                            || entry
                                .path()
                                .read_dir()
                                .is_ok_and(|mut children| children.next().is_some())
                    })
                });
                if !has_material_entry {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("epoch N+1 process retained its ownership channel");
    }

    let shutdown_started = tokio::time::Instant::now();
    let shutdown_result = executor.shutdown().await;
    match kind {
        "stale_epoch" => assert!(shutdown_result.is_err()),
        "hang" if shutdown_result.is_err() => {
            let launch_after_shutdown = store.load_launch(launch_attempt).await.unwrap();
            assert_eq!(
                launch_after_shutdown.state,
                navigator_store_api::LaunchState::CleanupRequired
            );
            assert_eq!(
                launch_after_shutdown
                    .cleanup_reason
                    .as_ref()
                    .map(BoundedText::as_str),
                Some("process identity or termination could not be proven")
            );
        }
        _ => {
            if let Err(error) = shutdown_result {
                panic!(
                    "{kind} shutdown failed after {:?}: {error:?}; launch={:?}",
                    shutdown_started.elapsed(),
                    store.load_launch(launch_attempt).await
                );
            }
            if kind != "catalog_mismatch" {
                assert_eq!(
                    store.load_launch(launch_attempt).await.unwrap().state,
                    navigator_store_api::LaunchState::Stopped
                );
            }
        }
    }
    if kind == "hang" {
        assert!(
            shutdown_started.elapsed() < Duration::from_millis(1_600),
            "hung Driver consumed more than the configured process-stop budget"
        );
    }
    let _ = ownership.shutdown().await;
    drop(service);
    drop(backend);
    let cleaned = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let has_material_entry = control_dir.read_dir().is_ok_and(|entries| {
                entries.filter_map(Result::ok).any(|entry| {
                    entry.file_name() != "credentials"
                        || !entry.file_type().is_ok_and(|kind| kind.is_dir())
                        || entry
                            .path()
                            .read_dir()
                            .is_ok_and(|mut children| children.next().is_some())
                })
            });
            if !has_material_entry {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        cleaned.is_ok(),
        "orphaned control entries: {:?}",
        control_dir
            .read_dir()
            .unwrap()
            .filter_map(Result::ok)
            .flat_map(|entry| {
                let path = entry.path();
                let children = path
                    .read_dir()
                    .map(|entries| {
                        entries
                            .filter_map(Result::ok)
                            .map(|child| child.path())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                std::iter::once(path).chain(children)
            })
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the real-process cancellation fixture keeps launch, abort, reconciliation, and residue oracles visible"
)]
async fn cancelled_pending_launch_is_reconciled_before_shutdown_returns() {
    use std::os::unix::fs::PermissionsExt as _;

    let _process_guard = PROCESS_TEST_LOCK.lock().await;
    let directory = tempfile::Builder::new()
        .prefix("navigator-pending-launch-")
        .tempdir_in("/tmp")
        .unwrap();
    let store = Arc::new(
        SqliteStore::open(directory.path().join("navigator.db"))
            .await
            .unwrap(),
    );
    let host = identity(HOST, HostId::from_uuid);
    let session = identity(80_002, SessionId::from_uuid);
    let participant = identity(80_003, ParticipantId::from_uuid);
    let operation = identity(80_004, OperationId::from_uuid);
    let message = identity(80_005, MessageId::from_uuid);
    let registered = template(fake_driver_id()).registration_snapshot();
    store
        .open_session(OpenSession::new(
            context(80_010),
            session,
            ConsumerKey::new("pending-launch-e2e").unwrap(),
            registered.compatibility,
        ))
        .await
        .unwrap();
    let lease = store
        .acquire_ownership(AcquireOwnership::new(
            context(80_011),
            session,
            LeaseDuration::from_millis(60_000).unwrap(),
        ))
        .await
        .unwrap()
        .value()
        .clone();
    store.register_template(registered.clone()).await.unwrap();
    store
        .create_root_participant(CreateRootParticipant {
            context: context(80_012),
            session_id: session,
            epoch: lease.epoch(),
            participant_id: participant,
            template_id: registered.identity,
            expected_compatibility: registered.compatibility,
        })
        .await
        .unwrap();
    let operation_snapshot = navigator_core::OperationPersistence::start(
        store.as_ref(),
        StartOperation {
            context: context(80_013),
            session_id: session,
            epoch: lease.epoch(),
            operation_id: operation,
            participant_id: participant,
            input_message_id: message,
            input: template(fake_driver_id()).validate_input(b"{}").unwrap(),
        },
    )
    .await
    .unwrap()
    .value()
    .clone();
    let operation_snapshot = navigator_core::OperationPersistence::transition(
        store.as_ref(),
        TransitionOperation {
            context: context(80_014),
            session_id: session,
            epoch: lease.epoch(),
            operation_id: operation,
            expected_revision: operation_snapshot.revision,
            action: OperationAction::BeginStart,
            report_message_id: None,
            terminal_outcome: None,
        },
    )
    .await
    .unwrap()
    .value()
    .clone();

    let marker = directory.path().join("spawned.pid");
    let scenario = directory.path().join("scenario.json");
    let journal = directory.path().join("journal.json");
    std::fs::write(&scenario, r#"{"events":[]}"#).unwrap();
    let control_dir = directory.path().join("runtime");
    std::fs::create_dir(&control_dir).unwrap();
    std::fs::set_permissions(&control_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let backend = Arc::new(UnixProcessBackend::new(control_dir.join("credentials")).unwrap());
    let supervisor = Arc::new(InstanceSupervisor::new(
        store.clone(),
        backend,
        Credentials,
        SupervisorConfig {
            graceful_timeout: Duration::from_millis(200),
            forced_timeout: Duration::from_millis(200),
            ownership_loss_timeout: Duration::from_millis(500),
        },
    ));
    let environment = BTreeMap::from([
        (
            OsString::from("NAVIGATOR_FAKE_DRIVER_SCENARIO_FILE"),
            scenario.into_os_string(),
        ),
        (
            OsString::from("NAVIGATOR_FAKE_DRIVER_JOURNAL_FILE"),
            journal.into_os_string(),
        ),
        (
            OsString::from("FAKE_DRIVER_PID_FILE"),
            marker.clone().into_os_string(),
        ),
        (
            OsString::from("FAKE_DRIVER_BEFORE_SOCKET_DELAY_MS"),
            OsString::from("1000"),
        ),
    ]);
    let config = SupervisedDriverConfig {
        bootstrap_configuration: Vec::new(),
        trusted_artifacts: Vec::new(),
        ownership_channel: OwnershipChannel::Stdin,
        process_io_mode: ProcessIoMode::Headless,
        driver_id: fake_driver_id(),
        program: fake_binary(),
        expected_executable_identity: executable_digest(),
        arguments: Vec::new(),
        working_directory: directory.path().to_path_buf(),
        environment_allowlist: environment.keys().cloned().collect(),
        environment,
        control_directory: control_dir.clone(),
        control_socket_environment: OsString::from("NAVIGATOR_CONTROL_SOCKET"),
        connect_timeout: Duration::from_secs(2),
        offered_capabilities: fake_offered_capabilities(),
    };
    let attempt = resolved_launch_attempt_for_config(
        participant,
        lease.epoch(),
        &config,
        &TrustedToolCatalog::new(serde_json::json!([])).unwrap(),
    )
    .unwrap();
    let expected_control_socket = supervisor.managed_control_socket_path(attempt);
    let expected_private_root = expected_control_socket.parent().unwrap().to_path_buf();
    let expected_credential = control_dir
        .join("credentials")
        .join(format!("{attempt}.credential"));
    let expected_bootstrap = control_dir
        .join("credentials")
        .join(format!("{attempt}.bootstrap.json"));
    let executor = Arc::new(SupervisedDriverExecutor::new(
        store.clone(),
        supervisor,
        host,
        config,
    ));
    let operation_executor = Arc::new(
        MailboxBackedOperationExecutor::new(
            store.clone(),
            executor.clone(),
            host,
            Duration::from_secs(2),
            Duration::from_millis(20),
            Duration::from_secs(1),
            Duration::from_secs(5),
            64,
        )
        .unwrap(),
    );
    let mut ready = tokio::spawn({
        let operation_executor = operation_executor.clone();
        async move { operation_executor.ensure_ready(&operation_snapshot).await }
    });
    let attached = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if ready.is_finished() {
                match (&mut ready).await {
                    Ok(Err(error)) => panic!("ensure_ready failed before launch: {error:?}"),
                    Ok(Ok(_)) => {
                        panic!("ensure_ready unexpectedly completed before delayed socket")
                    }
                    Err(error) => panic!("ensure_ready task failed before launch: {error:?}"),
                }
            }
            if marker.exists()
                && store
                    .load_launch(attempt)
                    .await
                    .is_ok_and(|launch| launch.state == navigator_store_api::LaunchState::Attached)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        attached.is_ok(),
        "launch never crossed durable Attached: launch={:?}, marker={:?}",
        store.load_launch(attempt).await,
        std::fs::read_to_string(&marker)
    );
    let pid: u32 = std::fs::read_to_string(&marker)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    ready.abort();
    assert!(matches!(ready.await, Err(error) if error.is_cancelled()));

    let shutdown = tokio::time::timeout(
        Duration::from_secs(15),
        executor.shutdown_with_deadline(tokio::time::Instant::now() + Duration::from_secs(10)),
    )
    .await
    .expect("pending launch shutdown exceeded its bound");
    if let Err(error) = shutdown {
        let private_root = expected_control_socket.parent().unwrap();
        let entries = std::fs::read_dir(private_root)
            .map(|values| {
                values
                    .filter_map(Result::ok)
                    .map(|value| value.path())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        panic!(
            "pending launch shutdown required manual cleanup: {error:?}; launch={:?}; private_root={:?}; entries={entries:?}",
            store.load_launch(attempt).await,
            std::fs::symlink_metadata(private_root)
        );
    }
    assert_eq!(
        store.load_launch(attempt).await.unwrap().state,
        navigator_store_api::LaunchState::Stopped
    );
    assert!(!expected_control_socket.exists());
    assert!(
        !expected_private_root.exists(),
        "cancelled pending launch left its attempt-private root"
    );
    assert!(
        !expected_credential.exists() && !expected_bootstrap.exists(),
        "cancelled pending launch left credential/bootstrap files"
    );
    let attempt_name = attempt.to_string();
    let residual_attempt_files = std::fs::read_dir(control_dir.join("credentials"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .filter(|name| name.to_string_lossy().contains(&attempt_name))
        .collect::<Vec<_>>();
    assert!(
        residual_attempt_files.is_empty(),
        "cancelled pending launch left attempt files: {residual_attempt_files:?}"
    );
    assert!(
        !std::process::Command::new("/bin/kill")
            .args(["-0", &pid.to_string()])
            .status()
            .unwrap()
            .success(),
        "cancelled pending Driver process remained alive"
    );
    // A zero-residual shutdown must succeed without any cleanup budget. If the
    // pending registry entry survived the proven stop, this call deterministically
    // fails before attempting a second reconciliation.
    executor
        .shutdown_with_deadline(tokio::time::Instant::now())
        .await
        .expect("proven pending cleanup left a registry or active-cache residue");
}

fn derived(domain: &[u8], session: Uuid, request: Uuid) -> Uuid {
    let digest = Sha256::new()
        .chain_update(domain)
        .chain_update(16_u64.to_be_bytes())
        .chain_update(session.as_bytes())
        .chain_update(16_u64.to_be_bytes())
        .chain_update(request.as_bytes())
        .finalize();
    let mut bytes: [u8; 16] = digest[..16].try_into().unwrap();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

#[expect(
    clippy::too_many_lines,
    reason = "the black-box oracle keeps Consumer transport, reconnect, persistence, and cleanup visible"
)]
async fn run_consumer_reconnect_case(cancel: bool) {
    let directory = FixtureDirectory::new("nav-consumer-e2e");
    let store = Arc::new(
        SqliteStore::open(directory.path().join("navigator.db"))
            .await
            .unwrap(),
    );
    let host = identity(500, HostId::from_uuid);
    let session = Uuid::from_u128(501);
    let start_request = Uuid::from_u128(502);
    let operation = derived(b"navigator.operation.v1", session, start_request);
    let message = derived(b"navigator.operation-input.v1", session, start_request);
    let scenario_path = directory.path().join("scenario.json");
    let cancel_marker = directory.path().join("allow-cancelled-report");
    let scenario = if cancel {
        serde_json::json!({"events":[{"kind":"outcome","operation_id":operation,"message_id":message,"outcome":"cancelled","wait_for_file":cancel_marker}]})
    } else {
        serde_json::json!({"events":[{"kind":"outcome","operation_id":operation,"message_id":message,"outcome":"succeeded"}]})
    };
    std::fs::write(&scenario_path, serde_json::to_vec(&scenario).unwrap()).unwrap();
    let control_dir = directory.path().join("control");
    std::fs::create_dir(&control_dir).unwrap();
    std::fs::set_permissions(
        &control_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let backend = Arc::new(UnixProcessBackend::new(control_dir.join("credentials")).unwrap());
    let supervisor = Arc::new(InstanceSupervisor::new(
        store.clone(),
        backend,
        Credentials,
        SupervisorConfig {
            graceful_timeout: Duration::from_millis(200),
            forced_timeout: Duration::from_millis(200),
            ownership_loss_timeout: Duration::from_millis(500),
        },
    ));
    let mut environment = BTreeMap::new();
    environment.insert(
        OsString::from("NAVIGATOR_FAKE_DRIVER_SCENARIO_FILE"),
        scenario_path.into_os_string(),
    );
    environment.insert(
        OsString::from("NAVIGATOR_FAKE_DRIVER_JOURNAL_FILE"),
        directory.path().join("journal.json").into_os_string(),
    );
    let allowlist = environment
        .keys()
        .cloned()
        .chain([OsString::from("NAVIGATOR_CONTROL_SOCKET")])
        .collect();
    let executor = Arc::new(SupervisedDriverExecutor::new(
        store.clone(),
        supervisor.clone(),
        host,
        SupervisedDriverConfig {
            bootstrap_configuration: Vec::new(),
            trusted_artifacts: Vec::new(),
            ownership_channel: OwnershipChannel::Stdin,
            process_io_mode: ProcessIoMode::Headless,
            driver_id: fake_driver_id(),
            program: fake_binary(),
            expected_executable_identity: executable_digest(),
            arguments: vec![],
            working_directory: directory.path().to_path_buf(),
            environment,
            environment_allowlist: allowlist,
            control_directory: control_dir.clone(),
            control_socket_environment: OsString::from("NAVIGATOR_CONTROL_SOCKET"),
            connect_timeout: if std::env::var_os("NAVIGATOR_EXTERNAL_FAULT_POINT").is_some() {
                Duration::from_secs(30)
            } else {
                Duration::from_secs(2)
            },
            offered_capabilities: fake_offered_capabilities(),
        },
    ));
    let operation_executor = Arc::new(
        MailboxBackedOperationExecutor::new(
            store.clone(),
            executor.clone(),
            host,
            Duration::from_secs(2),
            Duration::from_millis(20),
            Duration::from_secs(1),
            Duration::from_secs(5),
            64,
        )
        .unwrap(),
    );
    let operations = Arc::new(FirstOperationService::new(
        store.clone(),
        operation_executor,
        Arc::new(DriverTransitionContexts { host_id: host }),
        1,
        FirstOperationConfig {
            capacity_wait: Duration::from_secs(1),
            report_deadline: Duration::from_millis(100),
        },
    ));
    let navigator = LocalNavigator::new(store, host, LeaseDuration::from_millis(60_000).unwrap())
        .with_operation_controller(operations);
    let consumer_socket = directory.path().join("consumer.sock");
    let credential = BootstrapCredential::from_bytes(b"consumer-e2e-secret".to_vec()).unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(serve(
        navigator,
        credential.clone(),
        ServerConfig {
            socket_path: consumer_socket.clone(),
            shutdown_timeout: Duration::from_secs(2),
        },
        shutdown_rx,
    ));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if std::fs::symlink_metadata(&consumer_socket).is_ok_and(|metadata| {
                std::os::unix::fs::FileTypeExt::is_socket(&metadata.file_type())
            }) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Consumer socket readiness deadline");

    let mut client = LocalClient::connect(&consumer_socket, &credential)
        .await
        .unwrap();
    client.negotiate().await.unwrap();
    let opened = client
        .open(
            Uuid::from_u128(503),
            session,
            "consumer-e2e".into(),
            consumer::RootTemplateSpecification {
                template_id: Uuid::from_u128(TEMPLATE).as_bytes().to_vec(),
                role: "root".into(),
                driver_id: fake_driver_id().as_uuid().as_bytes().to_vec(),
                required_capabilities: vec![],
                trusted_configuration: Some(consumer::TrustedTemplateConfiguration {
                    base_instructions: "e2e".into(),
                    secret_names: vec![],
                }),
                resources: Some(consumer::ParticipantResourceBounds {
                    memory_bytes: 1024,
                    cpu_millis: 1000,
                    max_concurrent_operations: 1,
                }),
                input_schema: Some(consumer::InputSchema { fields: vec![] }),
                authority_profile: None,
            },
            None,
        )
        .await
        .unwrap();
    let root = match opened.outcome.unwrap() {
        consumer::open_session_response::Outcome::Snapshot(value) => {
            Uuid::from_slice(&value.root_participant_id).unwrap()
        }
        consumer::open_session_response::Outcome::Failure(_) => panic!("open failed"),
    };
    let started = client
        .start_operation(start_request, session, root, b"{}".to_vec())
        .await
        .unwrap();
    let admitted = match started.outcome {
        Some(consumer::start_operation_response::Outcome::Snapshot(value)) => value,
        Some(consumer::start_operation_response::Outcome::Failure(failure)) => {
            panic!("start failed: {failure:?}")
        }
        None => panic!("start returned no outcome"),
    };
    assert_eq!(admitted.operation_id, operation.as_bytes());
    assert_eq!(admitted.session_id, session.as_bytes());
    assert_eq!(admitted.participant_id, root.as_bytes());
    assert_eq!(admitted.request_id, start_request.as_bytes());
    assert_eq!(admitted.status, consumer::OperationStatus::Queued as i32);
    drop(client);

    let mut observer = LocalClient::connect(&consumer_socket, &credential)
        .await
        .unwrap();
    observer.negotiate().await.unwrap();
    if cancel {
        loop {
            let response = observer
                .operation_snapshot(session, operation)
                .await
                .unwrap();
            if matches!(response.outcome, Some(consumer::operation_snapshot_response::Outcome::Snapshot(ref value)) if value.status == consumer::OperationStatus::Running as i32)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        let response = observer
            .cancel_subtree(Uuid::from_u128(504), session, root)
            .await
            .unwrap();
        let cancellation = match response.outcome {
            Some(consumer::cancel_subtree_response::Outcome::Cancellation(value)) => value,
            other => panic!(
                "cancel failed: {other:?}; journal={:?}",
                std::fs::read_to_string(directory.path().join("journal.json"))
            ),
        };
        assert_eq!(cancellation.operations.len(), 1);
        if !cancellation.operations[0].driver_acknowledged {
            let diagnostic = SqliteStore::open(directory.path().join("navigator.db"))
                .await
                .unwrap()
                .load_message(identity(
                    Uuid::from_slice(&cancellation.operations[0].notification_message_id)
                        .unwrap()
                        .as_u128(),
                    MessageId::from_uuid,
                ))
                .await
                .unwrap();
            panic!(
                "cancel notification was not acknowledged: {:?}",
                diagnostic.state
            );
        }
        assert_eq!(
            cancellation.operations[0]
                .operation
                .as_ref()
                .unwrap()
                .status,
            consumer::OperationStatus::Cancelling as i32
        );
        let premature_close = observer.close(Uuid::from_u128(505), session).await.unwrap();
        let close_operation = observer
            .operation_snapshot(session, operation)
            .await
            .unwrap();
        assert!(
            matches!(
                premature_close.outcome,
                Some(consumer::close_session_response::Outcome::Failure(ref failure))
                    if failure.code == consumer::FailureCode::CleanupRequired as i32
            ),
            "premature close outcome: {:?}",
            (premature_close.outcome, close_operation.outcome)
        );
        let still_open = observer.snapshot(session).await.unwrap();
        assert!(matches!(
            still_open.outcome,
            Some(consumer::snapshot_response::Outcome::Snapshot(ref snapshot))
                if snapshot.status != consumer::SessionStatus::Closed as i32
        ));
        std::fs::write(&cancel_marker, b"committed").unwrap();
        let retry = observer
            .cancel_subtree(Uuid::from_u128(504), session, root)
            .await
            .unwrap();
        assert!(matches!(
            retry.outcome,
            Some(consumer::cancel_subtree_response::Outcome::Cancellation(_))
        ));
    }
    let terminal = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let response = observer
                .operation_snapshot(session, operation)
                .await
                .unwrap();
            if let Some(consumer::operation_snapshot_response::Outcome::Snapshot(value)) =
                response.outcome
            {
                let expected = if cancel {
                    consumer::OperationStatus::Cancelled
                } else {
                    consumer::OperationStatus::Succeeded
                };
                if value.status == expected as i32 {
                    break value;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "terminal timeout; journal={:?}",
            std::fs::read_to_string(directory.path().join("journal.json"))
        )
    });
    assert_eq!(terminal.operation_id, operation.as_bytes());
    assert_eq!(terminal.session_id, session.as_bytes());
    assert_eq!(terminal.participant_id, root.as_bytes());
    assert_eq!(terminal.request_id, start_request.as_bytes());
    assert_eq!(
        terminal.result.as_deref(),
        (!cancel).then_some([].as_slice())
    );
    if cancel {
        assert_eq!(
            terminal.terminal_failure.as_ref().unwrap().code,
            consumer::FailureCode::Cancelled as i32
        );
    } else {
        assert!(terminal.terminal_failure.is_none());
    }
    if cancel {
        let replay = observer
            .cancel_subtree(Uuid::from_u128(504), session, root)
            .await
            .unwrap();
        let replay = match replay.outcome {
            Some(consumer::cancel_subtree_response::Outcome::Cancellation(value)) => value,
            other => panic!("cancel replay failed: {other:?}"),
        };
        assert!(replay.operations[0].driver_acknowledged);
    }
    let persisted = SqliteStore::open(directory.path().join("navigator.db"))
        .await
        .unwrap();
    let events = persisted
        .read_events(ReadEvents {
            session_id: identity(501, SessionId::from_uuid),
            consumer: ConsumerKey::new("consumer-e2e").unwrap(),
            after: None,
            limit: EventReadLimit::new(64).unwrap(),
        })
        .await
        .unwrap();
    let operation_events = events
        .events
        .iter()
        .filter(|event| event.event_type().as_str().starts_with("operation."))
        .map(|event| event.event_type().as_str())
        .collect::<Vec<_>>();
    let expected_events = if cancel {
        vec![
            "operation.queued",
            "operation.starting",
            "operation.running",
            "operation.cancelling",
            "operation.cancelled",
        ]
    } else {
        vec![
            "operation.queued",
            "operation.starting",
            "operation.running",
            "operation.succeeded",
        ]
    };
    assert_eq!(operation_events, expected_events);

    if cancel {
        let event_types = events
            .events
            .iter()
            .map(|event| event.event_type().as_str())
            .collect::<Vec<_>>();
        let accepted = event_types
            .iter()
            .position(|value| *value == "message.accepted")
            .unwrap();
        let terminal_position = event_types
            .iter()
            .position(|value| *value == "operation.cancelled")
            .unwrap();
        assert!(accepted < terminal_position);
        let participant = identity(root.as_u128(), ParticipantId::from_uuid);
        let controls = persisted
            .load_mailbox(participant)
            .await
            .unwrap()
            .into_iter()
            .filter(|message| {
                matches!(
                    message.envelope.body(),
                    navigator_domain::MessageBody::Control {
                        command: ControlMessageKind::Cancel,
                        ..
                    }
                ) && matches!(
                    message.state,
                    navigator_store_api::MessageDeliveryState::Accepted { .. }
                )
            })
            .count();
        assert_eq!(controls, 1);
        let journal: serde_json::Value =
            serde_json::from_slice(&std::fs::read(directory.path().join("journal.json")).unwrap())
                .unwrap();
        assert_eq!(journal["cancel_count"], 1);
        assert_eq!(journal["delivery_count"], 1);
        assert_eq!(journal["accepted"].as_object().unwrap().len(), 1);
        assert_eq!(journal["cancelled"].as_array().unwrap().len(), 1);
    }

    let closed = observer
        .close(Uuid::from_u128(505), session)
        .await
        .expect("composed Session Close crosses the Consumer boundary");
    assert!(matches!(
        closed.outcome,
        Some(consumer::close_session_response::Outcome::Snapshot(ref snapshot))
            if snapshot.status == consumer::SessionStatus::Closed as i32
    ));
    shutdown_tx.send(true).unwrap();
    server.await.unwrap().unwrap();
    let remaining = control_dir
        .read_dir()
        .unwrap()
        .map(|entry| entry.unwrap())
        .collect::<Vec<_>>();
    assert!(remaining.iter().all(|entry| {
        entry.file_name() == "credentials"
            && entry.file_type().unwrap().is_dir()
            && !entry.path().read_dir().unwrap().any(|child| child.is_ok())
    }));
}

#[tokio::test]
async fn consumer_reconnect_observes_real_driver_terminal_and_ordered_events() {
    let _process_guard = PROCESS_TEST_LOCK.lock().await;
    run_consumer_reconnect_case(false).await;
}

#[tokio::test]
async fn consumer_cancellation_crosses_uds_store_and_real_driver_ack_boundary() {
    let _process_guard = PROCESS_TEST_LOCK.lock().await;
    run_consumer_reconnect_case(true).await;
}

#[tokio::test]
async fn sqlite_owned_template_operation_runs_through_real_supervised_driver() {
    let _process_guard = PROCESS_TEST_LOCK.lock().await;
    run_case("success", OperationState::Succeeded, 100).await;
    run_case("failure", OperationState::Failed, 200).await;
    run_case("idle", OperationState::Failed, 300).await;
    run_case("catalog_mismatch", OperationState::Failed, 400).await;
    run_case("stale_epoch", OperationState::Succeeded, 500).await;
    run_case("hang", OperationState::Uncertain, 600).await;
}

#[derive(Clone, Copy)]
enum ExternalDriverArea {
    Launch,
    Delivery,
    Report,
    Cancellation,
}

struct ExternalDriverStoreFacts {
    duplicate_roots: i64,
    duplicate_unfinished_operations: i64,
    orphan_rows: i64,
    unfinished_operations: i64,
    terminal_operations: i64,
    cleanup_launches: i64,
    unfinished_launches: i64,
}

async fn external_driver_store_facts(store: &SqliteStore) -> ExternalDriverStoreFacts {
    let duplicate_roots = sqlx::query_scalar(
        "SELECT COUNT(*) FROM (SELECT session_id FROM participants
         WHERE parent_participant_id IS NULL GROUP BY session_id HAVING COUNT(*)>1)",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    let duplicate_unfinished_operations = sqlx::query_scalar(
        "SELECT COUNT(*) FROM (SELECT participant_id FROM operations
         WHERE terminal_outcome IS NULL GROUP BY participant_id HAVING COUNT(*)>1)",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    let foreign_keys: i64 = sqlx::query("PRAGMA foreign_key_check")
        .fetch_all(store.pool())
        .await
        .unwrap()
        .len()
        .try_into()
        .unwrap();
    let capacity_pairs: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM capacity_reservations r
         LEFT JOIN capacity_global_reservations g ON g.reservation_id=r.reservation_id
         WHERE g.reservation_id IS NULL OR r.resource<>g.resource OR r.amount<>g.amount OR r.released<>g.released",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    let effect_bindings: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM effect_journal e
         LEFT JOIN participants p ON p.participant_id=e.participant_id AND p.session_id=e.session_id
         LEFT JOIN operations o ON o.operation_id=e.operation_id AND o.session_id=e.session_id
         WHERE p.participant_id IS NULL OR o.operation_id IS NULL",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    ExternalDriverStoreFacts {
        duplicate_roots,
        duplicate_unfinished_operations,
        orphan_rows: foreign_keys + capacity_pairs + effect_bindings,
        unfinished_operations: sqlx::query_scalar(
            "SELECT COUNT(*) FROM operations WHERE terminal_outcome IS NULL",
        )
        .fetch_one(store.pool())
        .await
        .unwrap(),
        terminal_operations: sqlx::query_scalar(
            "SELECT COUNT(*) FROM operations WHERE terminal_outcome IS NOT NULL",
        )
        .fetch_one(store.pool())
        .await
        .unwrap(),
        cleanup_launches: sqlx::query_scalar(
            "SELECT COUNT(*) FROM launch_attempts WHERE state='cleanup_required'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap(),
        unfinished_launches: sqlx::query_scalar(
            "SELECT COUNT(*) FROM launch_attempts WHERE state NOT IN ('stopped','cleanup_required')",
        )
        .fetch_one(store.pool())
        .await
        .unwrap(),
    }
}

async fn stale_predecessor_write_is_rejected(store: &SqliteStore, session: SessionId) -> bool {
    let predecessor_host = identity(990_001, HostId::from_uuid);
    let predecessor = match store.read_ownership(session).await.unwrap() {
        navigator_domain::OwnershipSnapshot::Owned {
            host_id,
            epoch,
            expires_at: _,
        } => {
            store
                .release_ownership(ReleaseOwnership::new(
                    RequestContext::new(identity(990_002, RequestId::from_uuid), host_id),
                    session,
                    epoch,
                ))
                .await
                .unwrap();
            (host_id, epoch)
        }
        navigator_domain::OwnershipSnapshot::Unowned => {
            let lease = store
                .acquire_ownership(AcquireOwnership::new(
                    RequestContext::new(identity(990_003, RequestId::from_uuid), predecessor_host),
                    session,
                    LeaseDuration::from_millis(60_000).unwrap(),
                ))
                .await
                .unwrap()
                .value()
                .clone();
            store
                .release_ownership(ReleaseOwnership::new(
                    RequestContext::new(identity(990_004, RequestId::from_uuid), predecessor_host),
                    session,
                    lease.epoch(),
                ))
                .await
                .unwrap();
            (predecessor_host, lease.epoch())
        }
    };
    let successor_host = identity(990_005, HostId::from_uuid);
    store
        .acquire_ownership(AcquireOwnership::new(
            RequestContext::new(identity(990_006, RequestId::from_uuid), successor_host),
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
                RequestContext::new(identity(990_007, RequestId::from_uuid), predecessor.0),
                session,
                predecessor.1,
                LeaseDuration::from_millis(60_000).unwrap(),
            ))
            .await,
        Err(navigator_store_api::StoreError::StaleOwnership { .. })
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

#[expect(
    clippy::too_many_lines,
    reason = "one parent oracle keeps subprocess crash, reopen, classification, and result facts together"
)]
async fn run_external_driver_fault_points(area: ExternalDriverArea, points: &[&str]) {
    // Each matrix launches the same real-process vertical in subprocesses. Keep
    // matrices and direct real-process verticals mutually exclusive in this
    // harness process so scheduler contention cannot manufacture a deadline
    // failure before the requested fault boundary is reached.
    let _process_guard = PROCESS_TEST_LOCK.lock().await;
    for &point in points {
        if std::env::var("NAVIGATOR_FAULT_MATRIX_ONLY").is_ok_and(|only| only != point) {
            continue;
        }
        let parent = tempfile::Builder::new()
            .prefix("nav-fault-parent-")
            .tempdir_in("/tmp")
            .unwrap();
        let root = parent.path().join("fixture");
        let observation = parent.path().join("observed");
        let mut unrelated = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let child_test = if matches!(area, ExternalDriverArea::Cancellation) {
            "consumer_cancellation_crosses_uds_store_and_real_driver_ack_boundary"
        } else {
            "sqlite_owned_template_operation_runs_through_real_supervised_driver"
        };
        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(child_test)
            .env("NAVIGATOR_DRIVER_FAULT_ROOT", &root)
            .env("NAVIGATOR_EXTERNAL_FAULT_POINT", point)
            .env("NAVIGATOR_EXTERNAL_FAULT_OBSERVATION", &observation)
            .status()
            .unwrap();
        assert!(!status.success(), "worker did not abort at {point}");
        assert_eq!(std::fs::read_to_string(&observation).unwrap(), point);

        let store = SqliteStore::open(root.join("navigator.db")).await.unwrap();
        let session = if matches!(area, ExternalDriverArea::Cancellation) {
            identity(501, SessionId::from_uuid)
        } else {
            identity(SESSION, SessionId::from_uuid)
        };
        let session_reloaded = store.load_session(session).await.unwrap().id() == session;
        assert!(session_reloaded);
        let durable = external_driver_store_facts(&store).await;
        let events = store
            .read_events(ReadEvents {
                session_id: session,
                consumer: ConsumerKey::new(if matches!(area, ExternalDriverArea::Cancellation) {
                    "consumer-e2e"
                } else {
                    "e2e"
                })
                .unwrap(),
                after: None,
                limit: EventReadLimit::new(128).unwrap(),
            })
            .await
            .unwrap();
        let events_strictly_ordered = events
            .events
            .windows(2)
            .all(|pair| pair[0].position() < pair[1].position());
        assert!(events_strictly_ordered);
        let driver_journal = std::fs::read(root.join("journal.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
        let accepted_count = driver_journal
            .as_ref()
            .and_then(|journal| journal.get("accepted"))
            .and_then(serde_json::Value::as_object)
            .map_or(0, serde_json::Map::len);
        let cancel_count = driver_journal
            .as_ref()
            .and_then(|journal| journal.get("cancel_count"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let report_sequence = driver_journal
            .as_ref()
            .and_then(|journal| journal.get("scripted_event_index"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let receipt_before = driver_journal.as_ref().map(|journal| {
            serde_json::json!({
                "accepted": journal.get("accepted"),
                "cancel_count": journal.get("cancel_count"),
            })
        });
        let ordinary_replay_receipt_unchanged = if accepted_count > 0 || cancel_count > 0 {
            let (operation_id, input): (String, Vec<u8>) = sqlx::query_as(
                "SELECT operation_id,input_payload FROM operations WHERE terminal_outcome IS NULL ORDER BY created_at_seconds LIMIT 1",
            )
            .fetch_one(store.pool())
            .await
            .unwrap();
            let operation_id =
                OperationId::from_uuid(Uuid::parse_str(&operation_id).unwrap()).unwrap();
            let operation = store.load_operation(operation_id).await.unwrap();
            let participant = store
                .load_participant(operation.participant_id)
                .await
                .unwrap();
            let template = navigator_domain::Template::try_from(
                store.load_template(participant.template_id).await.unwrap(),
            )
            .unwrap();
            let navigator_domain::OwnershipSnapshot::Owned {
                host_id,
                epoch,
                expires_at: _,
            } = store.read_ownership(session).await.unwrap()
            else {
                panic!("ordinary replay requires the observed current owner")
            };
            let replay = store
                .start_operation(StartOperation {
                    context: RequestContext::new(operation.start_request_id, host_id),
                    session_id: operation.session_id,
                    epoch,
                    operation_id: operation.operation_id,
                    participant_id: operation.participant_id,
                    input_message_id: operation.input_message_id,
                    input: template.validate_input(&input).unwrap(),
                })
                .await
                .unwrap();
            assert!(matches!(replay, navigator_store_api::Mutation::Replayed(_)));
            let journal_after: serde_json::Value =
                serde_json::from_slice(&std::fs::read(root.join("journal.json")).unwrap()).unwrap();
            receipt_before
                == Some(serde_json::json!({
                    "accepted": journal_after.get("accepted"),
                    "cancel_count": journal_after.get("cancel_count"),
                }))
        } else {
            true
        };
        let stale_owner_cannot_commit = stale_predecessor_write_is_rejected(&store, session).await;
        let unrelated_process_survived = unrelated.try_wait().unwrap().is_none();
        assert!(
            unrelated_process_survived,
            "driver recovery at {point} terminated an unrelated process"
        );
        unrelated.kill().unwrap();
        unrelated.wait().unwrap();
        if let Some(result_path) = std::env::var_os("NAVIGATOR_FAULT_CASE_RESULT") {
            let actual = match area {
                ExternalDriverArea::Launch
                    if durable.cleanup_launches > 0 || durable.unfinished_launches > 0 =>
                {
                    "cleanup_required"
                }
                ExternalDriverArea::Delivery if accepted_count > 0 => "uncertain",
                ExternalDriverArea::Cancellation if cancel_count > 0 => "uncertain",
                ExternalDriverArea::Report if durable.terminal_operations > 0 => "terminal",
                ExternalDriverArea::Launch
                | ExternalDriverArea::Delivery
                | ExternalDriverArea::Cancellation
                | ExternalDriverArea::Report => "recoverable",
            };
            let classified_final_state = match actual {
                "terminal" => durable.terminal_operations > 0,
                "recoverable" => durable.unfinished_operations > 0,
                "uncertain" => accepted_count > 0 || cancel_count > 0,
                "cleanup_required" => {
                    durable.cleanup_launches > 0 || durable.unfinished_launches > 0
                }
                _ => false,
            };
            let no_orphan_reservation = durable.orphan_rows == 0;
            std::fs::write(
                result_path,
                serde_json::to_vec(&serde_json::json!({
                    "schema_version": 1,
                    "seed": std::env::var("NAVIGATOR_FAULT_CASE_SEED").unwrap().parse::<u64>().unwrap(),
                    "fault_point": point,
                    "actual_classification": actual,
                    "facts": {
                        "no_duplicate_unfinished_participant": durable.duplicate_roots == 0,
                        "no_duplicate_unfinished_operation": durable.duplicate_unfinished_operations == 0,
                        "no_orphan_reservation": no_orphan_reservation,
                        "uncertain_effect_not_ordinarily_replayed": actual != "uncertain" || ordinary_replay_receipt_unchanged,
                        "stale_owner_cannot_commit": stale_owner_cannot_commit,
                        "unrelated_process_not_terminated": unrelated_process_survived,
                        "classified_final_state": classified_final_state
                    },
                    "diagnostics": {
                        "observation_schema": "external-driver-v2",
                        "sqlite_reopened": true,
                        "session_reloaded": session_reloaded,
                        "event_count": events.events.len(),
                        "driver_journal_present": driver_journal.is_some(),
                        "accepted_count": accepted_count,
                        "cancel_count": cancel_count,
                        "report_sequence": report_sequence,
                        "events_strictly_ordered": events_strictly_ordered,
                        "duplicate_roots": durable.duplicate_roots,
                        "duplicate_unfinished_operations": durable.duplicate_unfinished_operations,
                        "orphan_rows": durable.orphan_rows,
                        "unfinished_operations": durable.unfinished_operations,
                        "terminal_operations": durable.terminal_operations,
                        "cleanup_launches": durable.cleanup_launches,
                        "unfinished_launches": durable.unfinished_launches,
                        "unrelated_process_survived": unrelated_process_survived,
                        "stale_predecessor_rejected_without_mutation": stale_owner_cannot_commit,
                        "external_receipt_unchanged_after_ordinary_replay": ordinary_replay_receipt_unchanged
                    }
                }))
                .unwrap(),
            )
            .unwrap();
        }
    }
}

#[tokio::test]
async fn external_launch_fault_matrix_reopens_observed_sqlite_state() {
    run_external_driver_fault_points(
        ExternalDriverArea::Launch,
        &[
            "launch.external.before_call",
            "launch.external.after_call",
            "launch.external.before_identity_proof",
            "launch.external.after_identity_proof",
        ],
    )
    .await;
}

#[tokio::test]
async fn external_delivery_fault_matrix_reopens_observed_sqlite_state() {
    run_external_driver_fault_points(
        ExternalDriverArea::Delivery,
        &[
            "delivery.external.before_call",
            "delivery.external.after_call",
            "delivery.external.before_acceptance_proof",
            "delivery.external.after_acceptance_proof",
        ],
    )
    .await;
}

#[tokio::test]
async fn external_report_fault_matrix_reopens_observed_sqlite_state() {
    run_external_driver_fault_points(
        ExternalDriverArea::Report,
        &[
            "report.external.before_call",
            "report.external.after_call",
            "report.external.before_correlation_proof",
            "report.external.after_correlation_proof",
        ],
    )
    .await;
}

#[tokio::test]
async fn external_cancellation_fault_matrix_reopens_observed_sqlite_state() {
    run_external_driver_fault_points(
        ExternalDriverArea::Cancellation,
        &[
            "cancellation.external.before_call",
            "cancellation.external.after_call",
            "cancellation.external.before_stop_proof",
            "cancellation.external.after_stop_proof",
        ],
    )
    .await;
}

#[tokio::test]
async fn competing_attempt_question_has_zero_hierarchy_side_effects() {
    let _process_guard = PROCESS_TEST_LOCK.lock().await;
    run_case("forged_question", OperationState::Uncertain, 700).await;
}

struct DeliveryContexts(AtomicU64);
impl DeliveryContextFactory for DeliveryContexts {
    fn context(&self, _message_id: Option<MessageId>, _phase: DeliveryPhase) -> RequestContext {
        context(2_000 + u128::from(self.0.fetch_add(1, Ordering::Relaxed)))
    }
    fn attempt_id(&self, _destination: ParticipantId) -> DeliveryAttemptId {
        identity(
            3_000 + u128::from(self.0.fetch_add(1, Ordering::Relaxed)),
            DeliveryAttemptId::from_uuid,
        )
    }
}

struct ScriptedMailboxDriver {
    deliveries: Mutex<VecDeque<Result<AcceptanceObservation, DeliveryDriverError>>>,
    queries: Mutex<VecDeque<Result<AcceptanceObservation, DeliveryDriverError>>>,
    delivered: Mutex<Vec<MessageId>>,
    payloads: Mutex<Vec<Vec<u8>>>,
}

struct BlockingMailboxDriver {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl MailboxDriver for BlockingMailboxDriver {
    async fn deliver(
        &self,
        _message: &navigator_store_api::MessageSnapshot,
        _lease: &navigator_store_api::DeliveryLease,
        _call_timeout: Duration,
    ) -> Result<AcceptanceObservation, DeliveryDriverError> {
        self.entered.notify_one();
        self.release.notified().await;
        Ok(AcceptanceObservation::Accepted {
            proof_digest: [6; 32],
        })
    }

    async fn query_acceptance(
        &self,
        _message_id: MessageId,
        _lease: &navigator_store_api::DeliveryLease,
        _call_timeout: Duration,
    ) -> Result<AcceptanceObservation, DeliveryDriverError> {
        Err(DeliveryDriverError)
    }
}

struct LoseDeliverReply<D> {
    inner: Arc<D>,
    lose_first_query: std::sync::atomic::AtomicBool,
}
impl<D: MailboxDriver> MailboxDriver for LoseDeliverReply<D> {
    async fn deliver(
        &self,
        message: &navigator_store_api::MessageSnapshot,
        lease: &navigator_store_api::DeliveryLease,
        call_timeout: Duration,
    ) -> Result<AcceptanceObservation, DeliveryDriverError> {
        self.inner.deliver(message, lease, call_timeout).await?;
        Err(DeliveryDriverError)
    }

    async fn query_acceptance(
        &self,
        message_id: MessageId,
        lease: &navigator_store_api::DeliveryLease,
        call_timeout: Duration,
    ) -> Result<AcceptanceObservation, DeliveryDriverError> {
        if self.lose_first_query.swap(false, Ordering::SeqCst) {
            return Err(DeliveryDriverError);
        }
        self.inner
            .query_acceptance(message_id, lease, call_timeout)
            .await
    }
}
impl MailboxDriver for ScriptedMailboxDriver {
    async fn deliver(
        &self,
        message: &navigator_store_api::MessageSnapshot,
        _lease: &navigator_store_api::DeliveryLease,
        _call_timeout: Duration,
    ) -> Result<AcceptanceObservation, DeliveryDriverError> {
        self.delivered.lock().unwrap().push(message.message_id);
        self.payloads
            .lock()
            .unwrap()
            .push(message.envelope.as_bytes().to_vec());
        self.deliveries
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(DeliveryDriverError))
    }
    async fn query_acceptance(
        &self,
        _message_id: MessageId,
        _lease: &navigator_store_api::DeliveryLease,
        _call_timeout: Duration,
    ) -> Result<AcceptanceObservation, DeliveryDriverError> {
        self.queries
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(DeliveryDriverError))
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one process fixture preserves the delivery crash-boundary sequence"
)]
async fn delivery_loop_prioritizes_control_and_never_reinjects_unknown() {
    let directory = tempfile::Builder::new()
        .prefix("nav-mailbox")
        .tempdir_in("/tmp")
        .unwrap();
    let store_clock = Arc::new(StoreClock::new(100));
    let store = Arc::new(
        SqliteStore::open_with_clock(
            directory.path().join("mailbox.db"),
            store_clock.clone(),
            LeaseDuration::from_millis(60_000).unwrap(),
        )
        .await
        .unwrap(),
    );
    let session = identity(SESSION, SessionId::from_uuid);
    let participant = identity(PARTICIPANT, ParticipantId::from_uuid);
    let host = identity(HOST, HostId::from_uuid);
    let registered = template(fake_driver_id()).registration_snapshot();
    store
        .open_session(OpenSession::new(
            context(1_900),
            session,
            ConsumerKey::new("mailbox-e2e").unwrap(),
            registered.compatibility,
        ))
        .await
        .unwrap();
    let lease = store
        .acquire_ownership(AcquireOwnership::new(
            context(1_901),
            session,
            LeaseDuration::from_millis(60_000).unwrap(),
        ))
        .await
        .unwrap()
        .value()
        .clone();
    store.register_template(registered.clone()).await.unwrap();
    store
        .create_root_participant(CreateRootParticipant {
            context: context(1_902),
            session_id: session,
            epoch: lease.epoch(),
            participant_id: participant,
            template_id: registered.identity,
            expected_compatibility: registered.compatibility,
        })
        .await
        .unwrap();
    let operation = store
        .start_operation(StartOperation {
            context: context(1_903),
            session_id: session,
            epoch: lease.epoch(),
            operation_id: identity(1_904, OperationId::from_uuid),
            participant_id: participant,
            input_message_id: identity(1_905, MessageId::from_uuid),
            input: template(fake_driver_id()).validate_input(b"{}").unwrap(),
        })
        .await
        .unwrap()
        .value()
        .clone();
    let scenario_path = directory.path().join("mailbox-scenario.json");
    std::fs::write(&scenario_path, r#"{"events":[]}"#).unwrap();
    let control_dir = directory.path().join("mailbox-control");
    std::fs::create_dir(&control_dir).unwrap();
    std::fs::set_permissions(
        &control_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let backend = Arc::new(UnixProcessBackend::new(control_dir.join("credentials")).unwrap());
    let supervisor = Arc::new(InstanceSupervisor::new(
        store.clone(),
        backend,
        Credentials,
        SupervisorConfig {
            graceful_timeout: Duration::from_millis(200),
            forced_timeout: Duration::from_millis(200),
            ownership_loss_timeout: Duration::from_millis(500),
        },
    ));
    let mut environment = BTreeMap::new();
    environment.insert(
        OsString::from("NAVIGATOR_FAKE_DRIVER_SCENARIO_FILE"),
        scenario_path.into_os_string(),
    );
    environment.insert(
        OsString::from("NAVIGATOR_FAKE_DRIVER_JOURNAL_FILE"),
        directory
            .path()
            .join("mailbox-journal.json")
            .into_os_string(),
    );
    let environment_allowlist: BTreeSet<OsString> = environment
        .keys()
        .cloned()
        .chain([OsString::from("NAVIGATOR_CONTROL_SOCKET")])
        .collect();
    let driver_config = SupervisedDriverConfig {
        bootstrap_configuration: Vec::new(),
        trusted_artifacts: Vec::new(),
        ownership_channel: OwnershipChannel::Stdin,
        process_io_mode: ProcessIoMode::Headless,
        driver_id: fake_driver_id(),
        program: fake_binary(),
        expected_executable_identity: executable_digest(),
        arguments: vec![],
        working_directory: directory.path().to_path_buf(),
        environment: environment.clone(),
        environment_allowlist: environment_allowlist.clone(),
        control_directory: control_dir.clone(),
        control_socket_environment: OsString::from("NAVIGATOR_CONTROL_SOCKET"),
        connect_timeout: Duration::from_secs(2),
        offered_capabilities: fake_offered_capabilities(),
    };
    let executor = Arc::new(SupervisedDriverExecutor::new(
        store.clone(),
        supervisor.clone(),
        host,
        driver_config.clone(),
    ));
    let ready_executor = MailboxBackedOperationExecutor::new(
        store.clone(),
        executor.clone(),
        host,
        Duration::from_secs(2),
        Duration::from_millis(20),
        Duration::from_secs(1),
        Duration::from_secs(5),
        64,
    )
    .unwrap();
    OperationExecutor::ensure_ready(&ready_executor, &operation)
        .await
        .unwrap();
    let real_launch_attempt = resolved_launch_attempt_for_config(
        participant,
        lease.epoch(),
        &driver_config,
        &TrustedToolCatalog::new(serde_json::json!([])).unwrap(),
    )
    .unwrap();
    let launch = store.load_launch(real_launch_attempt).await.unwrap();
    let real_instance = launch.instance_id.unwrap();
    let ordinary = operation.input_message_id;
    let enqueue = |request_value, message_value, kind| {
        let message_id = identity(message_value, MessageId::from_uuid);
        let (envelope, in_reply_to) = match kind {
            MessageKind::OperationInput => (
                ValidatedMessageEnvelope::operation_input(
                    operation.operation_id,
                    operation.input_digest,
                ),
                None,
            ),
            MessageKind::Control => (
                ValidatedMessageEnvelope::control(
                    operation.operation_id,
                    ControlMessageKind::Reminder,
                ),
                None,
            ),
            MessageKind::CorrelatedFeedback => (
                ValidatedMessageEnvelope::correlated_feedback(
                    operation.operation_id,
                    ordinary,
                    FeedbackKind::Acknowledged,
                ),
                Some(ordinary),
            ),
            MessageKind::Question => panic!("question messages are produced by hierarchy flow"),
            MessageKind::OperationOutcome => {
                panic!("operation outcomes are produced by terminal transitions")
            }
            MessageKind::ApprovalDecision => {
                panic!("approval decisions are produced by the trusted approval flow")
            }
        };
        EnqueueMessage {
            context: context(request_value),
            session_id: session,
            epoch: lease.epoch(),
            message_id,
            source: participant,
            destination: participant,
            correlation: MessageCorrelation {
                operation_id: Some(operation.operation_id),
                in_reply_to,
            },
            envelope,
        }
    };
    let control = identity(1_913, MessageId::from_uuid);
    let real_control = identity(1_914, MessageId::from_uuid);
    let recovered = identity(1_915, MessageId::from_uuid);
    store
        .enqueue_message(enqueue(1_912, 1_913, MessageKind::Control))
        .await
        .unwrap();
    store
        .enqueue_message(enqueue(1_913, 1_914, MessageKind::Control))
        .await
        .unwrap();
    store
        .enqueue_message(enqueue(1_914, 1_915, MessageKind::CorrelatedFeedback))
        .await
        .unwrap();
    let commands = Arc::new(Commands(AtomicU64::new(900)));
    let ownership = OwnershipSupervisor::start(
        store.clone(),
        store_clock.clone(),
        commands.clone(),
        commands,
        lease.clone(),
        OwnershipConfig {
            lease_duration: LeaseDuration::from_millis(60_000).unwrap(),
            renewal_period: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(1),
        },
    )
    .unwrap();
    let permit = ownership.admission().admit().unwrap();
    let blocking_driver = Arc::new(BlockingMailboxDriver {
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let first_loop = Arc::new(
        DeliveryLoop::new(
            store.clone(),
            blocking_driver.clone(),
            Arc::new(DeliveryContexts(AtomicU64::new(600))),
            Duration::from_secs(2),
            Duration::from_secs(60),
            Duration::from_millis(100),
        )
        .unwrap(),
    );
    let second_loop = DeliveryLoop::new(
        store.clone(),
        blocking_driver.clone(),
        Arc::new(DeliveryContexts(AtomicU64::new(650))),
        Duration::from_secs(1),
        Duration::from_secs(60),
        Duration::from_millis(100),
    )
    .unwrap();
    let first_permit = permit.clone();
    let delivery_epoch = lease.epoch();
    let first = tokio::spawn(async move {
        first_loop
            .drive_once(
                &first_permit,
                session,
                delivery_epoch,
                participant,
                real_instance,
                real_launch_attempt,
            )
            .await
    });
    blocking_driver.entered.notified().await;
    assert_eq!(
        second_loop
            .drive_once(
                &permit,
                session,
                lease.epoch(),
                participant,
                real_instance,
                real_launch_attempt,
            )
            .await
            .unwrap(),
        DeliveryStep::Empty,
        "a second loop must not bypass the live mailbox lease"
    );
    blocking_driver.release.notify_one();
    assert_eq!(
        first.await.unwrap().unwrap(),
        DeliveryStep::Accepted(control)
    );
    let real_delivery = SupervisedMailboxWorker::new(
        store.clone(),
        executor.clone(),
        host,
        Duration::from_secs(2),
        Duration::from_secs(60),
        Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(
        real_delivery
            .drive_once(
                &permit,
                session,
                lease.epoch(),
                participant,
                real_instance,
                real_launch_attempt,
            )
            .await
            .unwrap(),
        DeliveryStep::Accepted(real_control),
        "mailbox delivery must cross the authenticated fake subprocess"
    );
    let driver = Arc::new(ScriptedMailboxDriver {
        deliveries: Mutex::new(VecDeque::from([Ok(AcceptanceObservation::Unknown)])),
        queries: Mutex::new(VecDeque::from([Ok(AcceptanceObservation::Unknown)])),
        delivered: Mutex::new(Vec::new()),
        payloads: Mutex::new(Vec::new()),
    });
    let delivery = DeliveryLoop::new(
        store.clone(),
        driver.clone(),
        Arc::new(DeliveryContexts(AtomicU64::new(0))),
        Duration::from_secs(1),
        Duration::from_millis(10),
        Duration::from_millis(100),
    )
    .unwrap();
    let instance = real_instance;
    assert_eq!(
        delivery
            .drive_once(
                &permit,
                session,
                lease.epoch(),
                participant,
                instance,
                real_launch_attempt,
            )
            .await
            .unwrap(),
        DeliveryStep::ReconciliationRequired(recovered)
    );
    assert_eq!(driver.delivered.lock().unwrap().as_slice(), &[recovered]);
    assert_eq!(
        delivery
            .drive_once(
                &permit,
                session,
                lease.epoch(),
                participant,
                instance,
                real_launch_attempt,
            )
            .await
            .unwrap(),
        DeliveryStep::Empty,
        "a live pending attempt must not be reconciled concurrently"
    );
    assert_eq!(
        driver.delivered.lock().unwrap().as_slice(),
        &[recovered],
        "unknown acceptance was blindly reinjected"
    );
    store_clock.set(101);
    assert_eq!(
        delivery
            .drive_once(
                &permit,
                session,
                lease.epoch(),
                participant,
                instance,
                real_launch_attempt,
            )
            .await
            .unwrap(),
        DeliveryStep::Uncertain(recovered)
    );
    assert!(matches!(
        store.load_message(recovered).await.unwrap().state,
        navigator_store_api::MessageDeliveryState::Uncertain { .. }
    ));
    let recovered_process = identity(1_919, MessageId::from_uuid);
    store
        .enqueue_message(enqueue(1_918, 1_919, MessageKind::CorrelatedFeedback))
        .await
        .unwrap();
    let lost_reply = DeliveryLoop::new(
        store.clone(),
        Arc::new(LoseDeliverReply {
            inner: executor.clone(),
            lose_first_query: std::sync::atomic::AtomicBool::new(true),
        }),
        Arc::new(DeliveryContexts(AtomicU64::new(800))),
        Duration::from_secs(1),
        Duration::from_secs(60),
        Duration::from_millis(100),
    )
    .unwrap();
    assert_eq!(
        lost_reply
            .drive_once(
                &permit,
                session,
                lease.epoch(),
                participant,
                real_instance,
                real_launch_attempt,
            )
            .await
            .unwrap(),
        DeliveryStep::ReconciliationRequired(recovered_process)
    );
    let pending = store.load_message(recovered_process).await.unwrap();
    let mut wrong_launch = match &pending.state {
        navigator_store_api::MessageDeliveryState::AcceptanceUnknown { lease } => lease.clone(),
        state => panic!("expected unknown acceptance, got {state:?}"),
    };
    wrong_launch.driver_launch_attempt_id = identity(9_999, LaunchAttemptId::from_uuid);
    assert!(
        MailboxDriver::deliver(
            executor.as_ref(),
            &pending,
            &wrong_launch,
            Duration::from_millis(100),
        )
        .await
        .is_err()
    );
    assert!(
        MailboxDriver::query_acceptance(
            executor.as_ref(),
            recovered_process,
            &wrong_launch,
            Duration::from_millis(100),
        )
        .await
        .is_err()
    );
    store_clock.set(102);
    executor.disconnect_controls_for_recovery().await;
    let restarted_executor = Arc::new(SupervisedDriverExecutor::new(
        store.clone(),
        supervisor,
        host,
        SupervisedDriverConfig {
            bootstrap_configuration: Vec::new(),
            trusted_artifacts: Vec::new(),
            ownership_channel: OwnershipChannel::Stdin,
            process_io_mode: ProcessIoMode::Headless,
            driver_id: fake_driver_id(),
            program: fake_binary(),
            expected_executable_identity: executable_digest(),
            arguments: vec![],
            working_directory: directory.path().to_path_buf(),
            environment,
            environment_allowlist,
            control_directory: control_dir,
            control_socket_environment: OsString::from("NAVIGATOR_CONTROL_SOCKET"),
            connect_timeout: Duration::from_secs(2),
            offered_capabilities: fake_offered_capabilities(),
        },
    ));
    let recovered_loop = SupervisedMailboxWorker::new(
        store.clone(),
        restarted_executor.clone(),
        host,
        Duration::from_secs(2),
        Duration::from_secs(60),
        Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(
        recovered_loop
            .drive_once(
                &permit,
                session,
                lease.epoch(),
                participant,
                real_instance,
                real_launch_attempt,
            )
            .await
            .unwrap(),
        DeliveryStep::Accepted(recovered_process),
        "a recreated executor must query durable acceptance, not reinject"
    );
    restarted_executor.shutdown().await.unwrap();
    executor.shutdown().await.unwrap();
    let _ = ownership.shutdown().await;
}
