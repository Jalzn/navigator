use navigator_domain::{
    BoundedBytes, BoundedText, Capability, CompatibilityIdentity, ConsumerKey, DriverId,
    DriverRequirement, FencingEpoch, HostId, InputField, InputKind, InputSchema, MessageId,
    OperationAction, OperationId, OperationState, ParticipantId, RequestId, ResourceBounds,
    Revision, SemanticDigest, SessionId, Template, TemplateId, TrustedConfiguration,
};
use navigator_store_api::{
    AcquireOwnership, CreateRootParticipant, EventReadLimit, LeaseDuration, MailboxStore, Mutation,
    OpenSession, OperationStore, OperationTerminalOutcome, ReadEvents, ReleaseOwnership,
    RequestContext, StartOperation, StoreError, TransitionOperation,
};
use uuid::Uuid;

pub const PRIVATE_EVENT_SENTINEL: &[u8] = b"PRIVATE_EVENT_PAYLOAD_SENTINEL";

pub trait OperationStoreFixture {
    type Store: OperationStore;
    fn store(&self) -> &Self::Store;
    fn set_wall_seconds(&self, seconds: i64);
    fn reopen(&mut self) -> impl Future<Output = Result<(), StoreError>> + Send;
    fn accept_causal_message(
        &self,
        session: SessionId,
        owner: HostId,
        epoch: FencingEpoch,
        participant: ParticipantId,
        message: MessageId,
    ) -> impl Future<Output = Result<(), String>> + Send;
}

pub async fn assert_operation_store_contract<F: OperationStoreFixture>(
    fixture: &mut F,
) -> Result<(), String>
where
    F::Store: MailboxStore,
{
    let (session, owner, epoch, participant, template) = setup(fixture.store()).await?;
    let mut scope = Scope {
        owner,
        session,
        epoch,
        participant,
    };
    fixture.set_wall_seconds(90);
    let (operation, message, start) = exercise_start(fixture, scope).await?;
    exercise_terminal(fixture.store(), scope, operation, message, &start).await?;
    scope.epoch = cross_epoch_replay(fixture.store(), scope, template, &start).await?;
    fixture
        .store()
        .start_operation(start_command(
            scope,
            823,
            operation_id(824),
            message_id(825),
            b"{}",
        )?)
        .await
        .map_err(debug)?;
    fixture.set_wall_seconds(200);
    let stale = start_command(scope, 830, operation_id(831), message_id(832), b"{}")?;
    if !matches!(
        fixture.store().start_operation(stale).await,
        Err(StoreError::OwnershipExpired { .. })
    ) {
        return Err("expired fencing authority admitted Operation mutation".into());
    }
    fixture.reopen().await.map_err(debug)?;
    verify_reopen(fixture.store(), scope, template, operation, message).await
}

async fn cross_epoch_replay<S: OperationStore>(
    store: &S,
    scope: Scope,
    template: TemplateId,
    start: &StartOperation,
) -> Result<FencingEpoch, String> {
    store
        .release_ownership(ReleaseOwnership::new(
            context(8990, scope.owner),
            scope.session,
            scope.epoch,
        ))
        .await
        .map_err(debug)?;
    let epoch = store
        .acquire_ownership(AcquireOwnership::new(
            context(8993, scope.owner),
            scope.session,
            LeaseDuration::from_millis(60_000).map_err(debug)?,
        ))
        .await
        .map_err(debug)?
        .value()
        .epoch();
    let root = CreateRootParticipant {
        context: context(809, scope.owner),
        session_id: scope.session,
        epoch,
        participant_id: participant_id(8994),
        template_id: template,
        expected_compatibility: store
            .load_template(template)
            .await
            .map_err(debug)?
            .compatibility,
    };
    if store
        .create_root_participant(root)
        .await
        .map_err(debug)?
        .value()
        .participant_id
        != scope.participant
    {
        return Err("root retry conflicted across ownership epoch".into());
    }
    let mut retry = start.clone();
    retry.epoch = epoch;
    if store
        .start_operation(retry)
        .await
        .map_err(debug)?
        .value()
        .operation_id
        != start.operation_id
    {
        return Err("Start retry conflicted across ownership epoch".into());
    }
    Ok(epoch)
}

#[derive(Clone, Copy)]
struct Scope {
    owner: HostId,
    session: SessionId,
    epoch: FencingEpoch,
    participant: ParticipantId,
}

async fn exercise_start<F: OperationStoreFixture>(
    fixture: &F,
    scope: Scope,
) -> Result<(OperationId, MessageId, StartOperation), String>
where
    F::Store: MailboxStore,
{
    let store = fixture.store();
    let operation = operation_id(810);
    let message = message_id(811);
    let start = start_command(
        scope,
        812,
        operation,
        message,
        br#"{"changed":true,"other":false}"#,
    )?;
    let applied = store.start_operation(start.clone()).await.map_err(debug)?;
    if !matches!(applied, Mutation::Applied(_)) {
        return Err("start did not apply".into());
    }
    let input_message = store.load_message(message).await.map_err(debug)?;
    let independent_digest = *SemanticDigest::v1(
        &Capability::new("operation.input.v1").map_err(debug)?,
        start.input.as_bytes(),
    )
    .as_bytes();
    if input_message.correlation.operation_id != Some(operation)
        || applied.value().input_digest != independent_digest
        || input_message.envelope
            != navigator_domain::ValidatedMessageEnvelope::operation_input(
                operation,
                independent_digest,
            )
    {
        return Err("operation and input Message were not one atomic fact".into());
    }
    let mut regenerated = start.clone();
    regenerated.operation_id = operation_id(813);
    regenerated.input_message_id = message_id(814);
    regenerated.input = operation_input(br#"{"other":false,"changed":true}"#)?;
    let replay = store.start_operation(regenerated).await.map_err(debug)?;
    if !matches!(replay, Mutation::Replayed(_))
        || replay.value().operation_id != operation
        || replay.value().input_message_id != message
    {
        return Err("semantic retry did not return original generated identities".into());
    }
    let mut changed = start.clone();
    changed.input = operation_input(br#"{"changed":true}"#)?;
    if !matches!(
        store.start_operation(changed).await,
        Err(StoreError::RequestConflict { .. })
    ) {
        return Err("changed input reused global request identity".into());
    }
    let duplicate = start_command(scope, 815, operation_id(816), message_id(817), b"{}")?;
    if store.start_operation(duplicate).await != Err(StoreError::Invalid) {
        return Err("duplicate unfinished Operation mutant survived".into());
    }
    transition_nonterminal(store, scope, operation, message, fixture).await?;
    Ok((operation, message, start))
}

async fn exercise_terminal<S: OperationStore>(
    store: &S,
    scope: Scope,
    operation: OperationId,
    message: MessageId,
    start: &StartOperation,
) -> Result<(), String> {
    let success = OperationTerminalOutcome::Succeeded {
        result: BoundedBytes::new(PRIVATE_EVENT_SENTINEL.to_vec()).map_err(debug)?,
    };
    let terminal = transition_command(
        scope,
        821,
        operation,
        3,
        OperationAction::ReportSuccess,
        Some(message),
        Some(success.clone()),
    );
    let snapshot = store
        .transition_operation(terminal)
        .await
        .map_err(debug)?
        .value()
        .clone();
    if snapshot.state != OperationState::Succeeded || snapshot.terminal_outcome != Some(success) {
        return Err("explicit success result was not durably committed".into());
    }
    let mut terminal_start_retry = start.clone();
    terminal_start_retry.operation_id = operation_id(8991);
    terminal_start_retry.input_message_id = message_id(8992);
    let current = store
        .start_operation(terminal_start_retry)
        .await
        .map_err(debug)?;
    if !matches!(current, Mutation::Replayed(_))
        || current.value().operation_id != operation
        || current.value().state != OperationState::Succeeded
        || current.value().revision != snapshot.revision
        || current.value().terminal_outcome != snapshot.terminal_outcome
    {
        return Err("Start retry did not return the current terminal Operation".into());
    }
    let terminal_mutant = transition_command(
        scope,
        822,
        operation,
        4,
        OperationAction::ReportFailure,
        Some(message),
        Some(OperationTerminalOutcome::Failed {
            code: BoundedText::new("mutant").map_err(debug)?,
            detail: BoundedText::new("must remain immutable").map_err(debug)?,
        }),
    );
    if store.transition_operation(terminal_mutant).await != Err(StoreError::Invalid) {
        return Err("terminal mutation mutant survived".into());
    }
    Ok(())
}

async fn verify_reopen<S: OperationStore>(
    store: &S,
    scope: Scope,
    template: TemplateId,
    operation: OperationId,
    message: MessageId,
) -> Result<(), String> {
    let root = store
        .load_root_participant(scope.session)
        .await
        .map_err(debug)?;
    if root.participant_id != scope.participant || root.template_id != template {
        return Err("exact root Participant was not recoverable by Session".into());
    }
    let registered = store.load_template(template).await.map_err(debug)?;
    let restored = Template::try_from(registered).map_err(debug)?;
    if restored.trusted_configuration().base_instructions() != "trusted-config"
        || restored.validate_input(b"{}").is_err()
    {
        return Err("trusted Template behavior was not recoverable after reopen".into());
    }
    let persisted = store.load_operation(operation).await.map_err(debug)?;
    if persisted.state != OperationState::Succeeded
        || store
            .load_operation_input(operation)
            .await
            .map_err(debug)?
            .as_slice()
            != br#"{"changed":true,"other":false}"#
    {
        return Err("Operation snapshot/input changed after reopen".into());
    }
    let events = store
        .read_events(ReadEvents {
            session_id: scope.session,
            consumer: ConsumerKey::new("operation-contract").map_err(debug)?,
            after: None,
            limit: EventReadLimit::new(100).map_err(debug)?,
        })
        .await
        .map_err(debug)?;
    let event_types = events
        .events
        .iter()
        .map(|event| event.event_type().as_str())
        .collect::<Vec<_>>();
    if events.events.windows(2).any(|pair| {
        pair[0].position() >= pair[1].position() || pair[0].occurred_at() > pair[1].occurred_at()
    }) || event_types
        != [
            "session.created",
            "ownership.acquired",
            "participant.created",
            "operation.queued",
            "message.enqueued",
            "operation.starting",
            "message.leased",
            "message.acceptance_pending",
            "message.accepted",
            "operation.running",
            "operation.succeeded",
            "ownership.released",
            "ownership.acquired",
            "operation.queued",
            "message.enqueued",
        ]
    {
        return Err("Operation state and ordered Event facts were not both visible".into());
    }
    let succeeded = events
        .events
        .iter()
        .find(|event| event.event_type().as_str() == "operation.succeeded")
        .ok_or_else(|| "terminal Event missing".to_owned())?;
    let payload: serde_json::Value =
        serde_json::from_slice(succeeded.data().as_slice()).map_err(debug)?;
    if payload["operation_id"] != operation.to_string()
        || payload["participant_id"] != scope.participant.to_string()
        || payload["input_message_id"] != message.to_string()
        || payload["state"] != "succeeded"
        || succeeded.related_request_id() != Some(request_id(821))
    {
        return Err("terminal Event did not identify its Operation transition".into());
    }
    if events.events.iter().any(|event| {
        event
            .data()
            .as_slice()
            .windows(PRIVATE_EVENT_SENTINEL.len())
            .any(|window| window == PRIVATE_EVENT_SENTINEL)
    }) {
        return Err("private Operation result reached a public Event payload".into());
    }
    Ok(())
}

async fn setup<S: OperationStore>(
    store: &S,
) -> Result<(SessionId, HostId, FencingEpoch, ParticipantId, TemplateId), String> {
    let session = session_id(800);
    let owner = host_id(801);
    let template = template_id(802);
    let registered = Template::register(
        template,
        BoundedText::new("root".to_owned()).map_err(debug)?,
        DriverRequirement::new(
            DriverId::from_uuid(Uuid::from_u128(803)).map_err(debug)?,
            vec![],
        )
        .map_err(debug)?,
        TrustedConfiguration::new(
            BoundedText::new("trusted-config".to_owned()).map_err(debug)?,
            [],
        )
        .map_err(debug)?,
        ResourceBounds::new(1024, 1000, 1).map_err(debug)?,
        operation_schema()?,
    )
    .map_err(debug)?;
    let compatibility = registered.compatibility();
    store
        .open_session(OpenSession::new(
            context(804, owner),
            session,
            ConsumerKey::new("operation-contract").map_err(debug)?,
            compatibility,
        ))
        .await
        .map_err(debug)?;
    let epoch = store
        .acquire_ownership(AcquireOwnership::new(
            context(805, owner),
            session,
            LeaseDuration::from_millis(60_000).map_err(debug)?,
        ))
        .await
        .map_err(debug)?
        .value()
        .epoch();
    let participant = participant_id(806);
    let root = CreateRootParticipant {
        context: context(807, owner),
        session_id: session,
        epoch,
        participant_id: participant,
        template_id: template,
        expected_compatibility: compatibility,
    };
    if store.create_root_participant(root.clone()).await != Err(StoreError::Invalid) {
        return Err("unregistered Template was accepted".into());
    }
    store
        .register_template(registered.registration_snapshot())
        .await
        .map_err(debug)?;
    let mut mismatch = root.clone();
    mismatch.context = context(808, owner);
    mismatch.expected_compatibility = CompatibilityIdentity::from_bytes([9; 32]);
    if store.create_root_participant(mismatch).await != Err(StoreError::Invalid) {
        return Err("Template compatibility mismatch was accepted".into());
    }
    let mut valid = root;
    valid.context = context(809, owner);
    store
        .create_root_participant(valid.clone())
        .await
        .map_err(debug)?;
    valid.participant_id = participant_id(899);
    let replay = store.create_root_participant(valid).await.map_err(debug)?;
    if !matches!(replay, Mutation::Replayed(_)) || replay.value().participant_id != participant {
        return Err("root retry did not preserve generated identity".into());
    }
    Ok((session, owner, epoch, participant, template))
}

async fn transition_nonterminal<S: OperationStore, F: OperationStoreFixture<Store = S>>(
    store: &S,
    scope: Scope,
    operation: OperationId,
    message: MessageId,
    fixture: &F,
) -> Result<(), String> {
    let begin = transition_command(
        scope,
        818,
        operation,
        1,
        OperationAction::BeginStart,
        None,
        None,
    );
    store
        .transition_operation(begin.clone())
        .await
        .map_err(debug)?;
    if !matches!(
        store.transition_operation(begin).await,
        Ok(Mutation::Replayed(_))
    ) {
        return Err("identical transition retry did not replay".into());
    }
    let missing = transition_command(
        scope,
        819,
        operation,
        2,
        OperationAction::ReportRunning,
        None,
        None,
    );
    if store.transition_operation(missing).await != Err(StoreError::Invalid) {
        return Err("report without delivery correlation was accepted".into());
    }
    let wrong = transition_command(
        scope,
        833,
        operation,
        2,
        OperationAction::ReportRunning,
        Some(message_id(999)),
        None,
    );
    if store.transition_operation(wrong).await != Err(StoreError::Invalid) {
        return Err("ambiguous report correlation was accepted".into());
    }
    fixture
        .accept_causal_message(
            scope.session,
            scope.owner,
            scope.epoch,
            scope.participant,
            message,
        )
        .await?;
    store
        .transition_operation(transition_command(
            scope,
            820,
            operation,
            2,
            OperationAction::ReportRunning,
            Some(message),
            None,
        ))
        .await
        .map_err(debug)?;
    let idle = transition_command(
        scope,
        826,
        operation,
        3,
        OperationAction::ObserveIdle,
        None,
        None,
    );
    if store.transition_operation(idle).await != Err(StoreError::Invalid) {
        return Err("idle=>success mutant survived".into());
    }
    Ok(())
}

fn start_command(
    scope: Scope,
    request: u128,
    operation: OperationId,
    message: MessageId,
    input: &[u8],
) -> Result<StartOperation, String> {
    Ok(StartOperation {
        context: context(request, scope.owner),
        session_id: scope.session,
        epoch: scope.epoch,
        operation_id: operation,
        participant_id: scope.participant,
        input_message_id: message,
        input: operation_input(input)?,
    })
}

fn operation_input(input: &[u8]) -> Result<navigator_domain::ValidatedTaskInput, String> {
    operation_schema()?.validate(input).map_err(debug)
}

fn operation_schema() -> Result<InputSchema, String> {
    InputSchema::new(vec![
        InputField::new(
            BoundedText::new("changed".to_owned()).map_err(debug)?,
            InputKind::Boolean,
            false,
            None,
        )
        .map_err(debug)?,
        InputField::new(
            BoundedText::new("other".to_owned()).map_err(debug)?,
            InputKind::Boolean,
            false,
            None,
        )
        .map_err(debug)?,
    ])
    .map_err(debug)
}

fn transition_command(
    scope: Scope,
    request: u128,
    operation: OperationId,
    revision: u64,
    action: OperationAction,
    report_message_id: Option<MessageId>,
    terminal_outcome: Option<OperationTerminalOutcome>,
) -> TransitionOperation {
    TransitionOperation {
        context: context(request, scope.owner),
        session_id: scope.session,
        epoch: scope.epoch,
        operation_id: operation,
        expected_revision: Revision::new(revision).expect("positive revision"),
        action,
        report_message_id,
        terminal_outcome,
    }
}

fn context(value: u128, owner: HostId) -> RequestContext {
    RequestContext::new(
        RequestId::from_uuid(Uuid::from_u128(value)).expect("id"),
        owner,
    )
}
fn request_id(value: u128) -> RequestId {
    RequestId::from_uuid(Uuid::from_u128(value)).expect("id")
}
fn session_id(value: u128) -> SessionId {
    SessionId::from_uuid(Uuid::from_u128(value)).expect("id")
}
fn host_id(value: u128) -> HostId {
    HostId::from_uuid(Uuid::from_u128(value)).expect("id")
}
fn template_id(value: u128) -> TemplateId {
    TemplateId::from_uuid(Uuid::from_u128(value)).expect("id")
}
fn participant_id(value: u128) -> ParticipantId {
    ParticipantId::from_uuid(Uuid::from_u128(value)).expect("id")
}
fn operation_id(value: u128) -> OperationId {
    OperationId::from_uuid(Uuid::from_u128(value)).expect("id")
}
fn message_id(value: u128) -> MessageId {
    MessageId::from_uuid(Uuid::from_u128(value)).expect("id")
}
fn debug(error: impl core::fmt::Debug) -> String {
    format!("{error:?}")
}
