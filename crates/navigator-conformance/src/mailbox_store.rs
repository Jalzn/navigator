use std::time::Duration;

use navigator_domain::{
    ConsumerKey, ControlMessageKind, DeliveryAttemptId, FeedbackKind, FencingEpoch, HostId,
    InstanceId, LaunchAttemptId, MessageId, OperationId, ParticipantId, RequestId, SessionId,
};
use navigator_store_api::{
    AcquireOwnership, DeliveryTransition, EnqueueMessage, EventReadLimit, LeaseDuration,
    LeaseNextMessage, MailboxStore, MessageCorrelation, MessageDeliveryState, MessagePriority,
    ReadEvents, ReleaseOwnership, RequestContext, SessionStore, StoreError,
    TransitionMessageDelivery,
};
use uuid::Uuid;

const PUBLIC_MESSAGE_EVENT_KEYS: [&str; 14] = [
    "schema_version",
    "session_id",
    "message_id",
    "source",
    "destination",
    "mailbox_sequence",
    "priority",
    "operation_id",
    "in_reply_to",
    "state",
    "attempt_count",
    "revision",
    "created_at",
    "updated_at",
];

#[derive(Clone, Copy)]
pub struct MailboxScope {
    pub session_id: SessionId,
    pub owner: HostId,
    pub epoch: FencingEpoch,
    pub source: ParticipantId,
    pub destination: ParticipantId,
    pub instance_id: InstanceId,
    pub launch_attempt_id: LaunchAttemptId,
    pub operation_id: OperationId,
    pub input_digest: [u8; 32],
}

pub trait MailboxStoreFixture {
    type Store: MailboxStore;
    fn store(&self) -> &Self::Store;
    fn prepare(&self) -> impl Future<Output = Result<MailboxScope, StoreError>> + Send;
    fn set_wall_seconds(&self, seconds: i64);
    fn reopen(&mut self) -> impl Future<Output = Result<(), StoreError>> + Send;
}

#[expect(
    clippy::too_many_lines,
    reason = "the contract is intentionally one ordered semantic scenario"
)]
pub async fn assert_mailbox_store_contract<F: MailboxStoreFixture>(
    fixture: &mut F,
) -> Result<(), String> {
    let mut scope = fixture.prepare().await.map_err(debug)?;
    let control = enqueue(scope, 11, 21, MessagePriority::Control, br"control");
    let first = fixture
        .store()
        .load_message(message_id(20))
        .await
        .map_err(|error| format!("atomic operation input missing: {error:?}"))?;
    if first
        .envelope
        .as_bytes()
        .windows(b"PRIVATE_MAILBOX_SENTINEL".len())
        .any(|window| window == b"PRIVATE_MAILBOX_SENTINEL")
        || format!("{:?}", first.envelope).contains("PRIVATE_MAILBOX_SENTINEL")
    {
        return Err("untrusted credential reached durable/debug Message payload".into());
    }
    let second = fixture
        .store()
        .enqueue_message(control)
        .await
        .map_err(debug)?
        .value()
        .clone();
    if (first.mailbox_sequence, second.mailbox_sequence) != (1, 2) {
        return Err("mailbox sequence is not gap-free".into());
    }
    let mut invalid = enqueue(
        scope,
        50,
        60,
        MessagePriority::Control,
        br#"{"feedback":true}"#,
    );
    invalid.correlation.in_reply_to = Some(message_id(61));
    invalid.envelope = navigator_domain::ValidatedMessageEnvelope::correlated_feedback(
        scope.operation_id,
        message_id(61),
        FeedbackKind::Acknowledged,
    );
    invalid.correlation.operation_id = Some(scope.operation_id);
    if fixture.store().enqueue_message(invalid.clone()).await != Err(StoreError::Invalid) {
        return Err("unknown correlation was accepted".into());
    }
    fixture
        .store()
        .enqueue_message(enqueue(
            scope,
            51,
            61,
            MessagePriority::Control,
            br#"{"request":true}"#,
        ))
        .await
        .map_err(debug)?;
    if fixture.store().enqueue_message(invalid.clone()).await != Err(StoreError::Invalid) {
        return Err("durable semantic failure changed after conditions changed".into());
    }
    invalid.envelope = navigator_domain::ValidatedMessageEnvelope::correlated_feedback(
        scope.operation_id,
        message_id(61),
        FeedbackKind::Rejected,
    );
    if !matches!(
        fixture.store().enqueue_message(invalid).await,
        Err(StoreError::RequestConflict { .. })
    ) {
        return Err("changed failed request input did not conflict".into());
    }
    let (left, right) = tokio::join!(
        fixture.store().enqueue_message(enqueue(
            scope,
            70,
            72,
            MessagePriority::Control,
            br#"{"n":1}"#
        )),
        fixture.store().enqueue_message(enqueue(
            scope,
            71,
            73,
            MessagePriority::Control,
            br#"{"n":2}"#
        )),
    );
    let mut concurrent = [
        left.map_err(debug)?.value().mailbox_sequence,
        right.map_err(debug)?.value().mailbox_sequence,
    ];
    concurrent.sort_unstable();
    if concurrent != [4, 5] {
        return Err("concurrent enqueue created duplicate/gapped sequence".into());
    }
    let leased = fixture
        .store()
        .lease_next_message(lease(scope, 30, 40))
        .await
        .map_err(debug)?
        .value()
        .clone()
        .ok_or("eligible Message missing")?;
    if leased.message_id != second.message_id {
        return Err("control priority did not precede ordinary FIFO".into());
    }
    let first_delivery_lease = match &leased.state {
        MessageDeliveryState::Leased { lease } => lease.clone(),
        _ => return Err("lease state missing".into()),
    };
    let retry_pending = fixture
        .store()
        .transition_message_delivery(TransitionMessageDelivery {
            context: context(23, scope.owner),
            session_id: scope.session_id,
            epoch: scope.epoch,
            message_id: leased.message_id,
            attempt_id: first_delivery_lease.attempt_id,
            expected_revision: leased.revision,
            transition: DeliveryTransition::AcceptancePending,
        })
        .await
        .map_err(debug)?
        .value()
        .clone();
    fixture
        .store()
        .transition_message_delivery(TransitionMessageDelivery {
            context: context(24, scope.owner),
            session_id: scope.session_id,
            epoch: scope.epoch,
            message_id: leased.message_id,
            attempt_id: first_delivery_lease.attempt_id,
            expected_revision: retry_pending.revision,
            transition: DeliveryTransition::RetryAfter {
                delay: Duration::from_secs(40),
            },
        })
        .await
        .map_err(debug)?;
    if fixture
        .store()
        .lease_next_message(lease(scope, 25, 39))
        .await
        .map_err(debug)?
        .value()
        .is_some()
    {
        return Err("delayed control head was bypassed by its class or ordinary class".into());
    }
    fixture.set_wall_seconds(140);
    let leased = fixture
        .store()
        .lease_next_message(lease(scope, 26, 39))
        .await
        .map_err(debug)?
        .value()
        .clone()
        .ok_or("due control head was not resumed")?;
    if leased.message_id != second.message_id {
        return Err("control FIFO changed after delayed head became due".into());
    }
    let first_delivery_lease = match &leased.state {
        MessageDeliveryState::Leased { lease } => lease.clone(),
        _ => return Err("cross-priority lease state missing".into()),
    };
    if fixture
        .store()
        .lease_next_message(lease(scope, 29, 39))
        .await
        .map_err(debug)?
        .value()
        .is_some()
    {
        return Err("a second Message bypassed the active mailbox lease".into());
    }
    fixture.set_wall_seconds(150);
    let expired_revision = leased.revision;
    let expired = fixture
        .store()
        .transition_message_delivery(TransitionMessageDelivery {
            context: context(31, scope.owner),
            session_id: scope.session_id,
            epoch: scope.epoch,
            message_id: leased.message_id,
            attempt_id: first_delivery_lease.attempt_id,
            expected_revision: leased.revision,
            transition: DeliveryTransition::AcceptancePending,
        })
        .await;
    if expired != Err(StoreError::Invalid)
        || fixture
            .store()
            .load_message(leased.message_id)
            .await
            .map_err(debug)?
            .revision
            != expired_revision
    {
        return Err("lease accepted at its exact expiry or mutated state".into());
    }
    let leased = fixture
        .store()
        .lease_next_message(lease(scope, 32, 41))
        .await
        .map_err(debug)?
        .value()
        .clone()
        .ok_or("expired Message was not re-leased")?;
    let delivery_lease = match &leased.state {
        MessageDeliveryState::Leased { lease } => lease.clone(),
        _ => return Err("replacement lease state missing".into()),
    };
    let pending = fixture
        .store()
        .transition_message_delivery(TransitionMessageDelivery {
            context: context(39, scope.owner),
            session_id: scope.session_id,
            epoch: scope.epoch,
            message_id: leased.message_id,
            attempt_id: delivery_lease.attempt_id,
            expected_revision: leased.revision,
            transition: DeliveryTransition::AcceptancePending,
        })
        .await
        .map_err(debug)?
        .value()
        .clone();
    fixture
        .store()
        .release_ownership(ReleaseOwnership::new(
            context(35, scope.owner),
            scope.session_id,
            scope.epoch,
        ))
        .await
        .map_err(debug)?;
    let previous_epoch = scope.epoch;
    scope.epoch = fixture
        .store()
        .acquire_ownership(AcquireOwnership::new(
            context(36, scope.owner),
            scope.session_id,
            LeaseDuration::from_millis(60_000).map_err(debug)?,
        ))
        .await
        .map_err(debug)?
        .value()
        .epoch();
    let stale = fixture
        .store()
        .transition_message_delivery(TransitionMessageDelivery {
            context: context(37, scope.owner),
            session_id: scope.session_id,
            epoch: previous_epoch,
            message_id: pending.message_id,
            attempt_id: delivery_lease.attempt_id,
            expected_revision: pending.revision,
            transition: DeliveryTransition::Accepted {
                proof_digest: [1; 32],
            },
        })
        .await;
    if !matches!(stale, Err(StoreError::StaleOwnership { .. })) {
        return Err("stale owner committed acceptance after takeover".into());
    }
    if fixture
        .store()
        .lease_next_message(lease(scope, 27, 42))
        .await
        .map_err(debug)?
        .value()
        .is_some()
    {
        return Err("live pending Driver effect was concurrently recovered".into());
    }
    fixture.set_wall_seconds(160);
    let recovered = fixture
        .store()
        .lease_next_message(lease(scope, 38, 41))
        .await
        .map_err(debug)?
        .value()
        .clone()
        .ok_or("pending acceptance orphaned")?;
    if recovered.message_id != pending.message_id
        || recovered.attempt_count != pending.attempt_count
    {
        return Err("reconciliation allocated a duplicate attempt".into());
    }
    let adopted = matches!(
        &recovered.state,
        MessageDeliveryState::AcceptancePending { lease }
            if lease.attempt_id == delivery_lease.attempt_id
                && lease.instance_id == delivery_lease.instance_id
                && lease.ownership_epoch == scope.epoch
                && lease.driver_ownership_epoch == previous_epoch
                && lease.driver_launch_attempt_id == scope.launch_attempt_id
    );
    if !adopted {
        return Err("takeover lost origin attempt/Instance binding".into());
    }
    fixture.set_wall_seconds(121);
    let accepted = fixture
        .store()
        .transition_message_delivery(TransitionMessageDelivery {
            context: context(33, scope.owner),
            session_id: scope.session_id,
            epoch: scope.epoch,
            message_id: recovered.message_id,
            attempt_id: delivery_lease.attempt_id,
            expected_revision: recovered.revision,
            transition: DeliveryTransition::Accepted {
                proof_digest: [7; 32],
            },
        })
        .await
        .map_err(debug)?
        .value()
        .clone();
    if !matches!(accepted.state, MessageDeliveryState::Accepted { .. }) {
        return Err("acceptance was not terminal".into());
    }
    let terminal_mutant = fixture
        .store()
        .transition_message_delivery(TransitionMessageDelivery {
            context: context(40, scope.owner),
            session_id: scope.session_id,
            epoch: scope.epoch,
            message_id: accepted.message_id,
            attempt_id: delivery_lease.attempt_id,
            expected_revision: accepted.revision,
            transition: DeliveryTransition::DeadLetter {
                reason: navigator_domain::BoundedText::new("mutant".to_owned()).map_err(debug)?,
            },
        })
        .await;
    if terminal_mutant != Err(StoreError::Invalid) {
        return Err("terminal Message mutated".into());
    }
    let stale_ready_binding = fixture
        .store()
        .lease_next_message(lease(scope, 34, 42))
        .await;
    if stale_ready_binding != Err(StoreError::Invalid) {
        return Err(
            "fresh lease relabelled a stale Ready Driver as the new ownership epoch".into(),
        );
    }
    fixture.reopen().await.map_err(debug)?;
    if fixture
        .store()
        .load_message(accepted.message_id)
        .await
        .map_err(debug)?
        != accepted
    {
        return Err("reopen changed accepted Message".into());
    }
    let events = fixture
        .store()
        .read_events(ReadEvents {
            session_id: scope.session_id,
            consumer: ConsumerKey::new("mailbox-contract").map_err(debug)?,
            after: None,
            limit: EventReadLimit::new(EventReadLimit::MAX).map_err(debug)?,
        })
        .await
        .map_err(debug)?;
    if events.events.windows(2).any(|pair| {
        pair[0].position() >= pair[1].position() || pair[0].occurred_at() > pair[1].occurred_at()
    }) {
        return Err("Message Event replay was not strictly ordered".into());
    }
    let mut event_ids = events
        .events
        .iter()
        .map(navigator_domain::SessionEvent::id)
        .collect::<Vec<_>>();
    event_ids.sort_unstable();
    event_ids.dedup();
    if event_ids.len() != events.events.len() {
        return Err("atomic facts reused an Event identity".into());
    }
    let message_events = events
        .events
        .iter()
        .filter(|event| event.event_type().as_str().starts_with("message."))
        .collect::<Vec<_>>();
    if message_events.is_empty()
        || !message_events
            .iter()
            .any(|event| event.event_type().as_str() == "message.accepted")
    {
        return Err("committed Message state was absent from Event replay".into());
    }
    let event_types = message_events
        .iter()
        .map(|event| event.event_type().as_str())
        .collect::<Vec<_>>();
    if event_types
        != [
            "message.enqueued",
            "message.enqueued",
            "message.enqueued",
            "message.enqueued",
            "message.enqueued",
            "message.leased",
            "message.acceptance_pending",
            "message.retry_scheduled",
            "message.leased",
            "message.leased",
            "message.acceptance_pending",
            "message.acceptance_pending",
            "message.accepted",
        ]
    {
        return Err("Message transition Event facts were omitted or reordered".into());
    }
    let requests = message_events
        .iter()
        .map(|event| event.related_request_id())
        .collect::<Vec<_>>();
    let concurrent_enqueues = [Some(request_id(70)), Some(request_id(71))];
    if requests[..3]
        != [
            Some(request_id(7015)),
            Some(request_id(11)),
            Some(request_id(51)),
        ]
        || !concurrent_enqueues.contains(&requests[3])
        || !concurrent_enqueues.contains(&requests[4])
        || requests[3] == requests[4]
        || requests[5..]
            != [
                Some(request_id(30)),
                Some(request_id(23)),
                Some(request_id(24)),
                Some(request_id(26)),
                Some(request_id(32)),
                Some(request_id(39)),
                Some(request_id(38)),
                Some(request_id(33)),
            ]
    {
        return Err("Message Events lost exact request correlation".into());
    }
    for event in message_events {
        let payload: serde_json::Value =
            serde_json::from_slice(event.data().as_slice()).map_err(debug)?;
        let fields = payload
            .as_object()
            .ok_or_else(|| "Message Event payload was not an object".to_owned())?;
        if fields
            .keys()
            .any(|key| !PUBLIC_MESSAGE_EVENT_KEYS.contains(&key.as_str()))
            || fields.get("message_id").is_none()
            || fields.get("state").is_none()
        {
            return Err("Message Event exposed private or omitted identifying facts".into());
        }
    }
    Ok(())
}

fn enqueue(
    scope: MailboxScope,
    request: u128,
    message: u128,
    priority: MessagePriority,
    payload: &[u8],
) -> EnqueueMessage {
    EnqueueMessage {
        context: context(request, scope.owner),
        session_id: scope.session_id,
        epoch: scope.epoch,
        message_id: message_id(message),
        source: scope.source,
        destination: scope.destination,
        correlation: MessageCorrelation {
            operation_id: Some(scope.operation_id),
            in_reply_to: None,
        },
        envelope: match priority {
            MessagePriority::Control => navigator_domain::ValidatedMessageEnvelope::control(
                scope.operation_id,
                if payload.len() % 2 == 0 {
                    ControlMessageKind::Cancel
                } else {
                    ControlMessageKind::Reminder
                },
            ),
            MessagePriority::Ordinary => {
                navigator_domain::ValidatedMessageEnvelope::operation_input(
                    scope.operation_id,
                    scope.input_digest,
                )
            }
        },
    }
}

fn lease(scope: MailboxScope, request: u128, attempt: u128) -> LeaseNextMessage {
    LeaseNextMessage {
        context: context(request, scope.owner),
        session_id: scope.session_id,
        epoch: scope.epoch,
        destination: scope.destination,
        instance_id: scope.instance_id,
        driver_launch_attempt_id: scope.launch_attempt_id,
        proposed_attempt_id: attempt_id(attempt),
        lease_duration: Duration::from_secs(10),
    }
}
fn context(value: u128, owner: HostId) -> RequestContext {
    RequestContext::new(request_id(value), owner)
}
fn request_id(value: u128) -> RequestId {
    RequestId::from_uuid(Uuid::from_u128(value)).unwrap()
}
fn message_id(value: u128) -> MessageId {
    MessageId::from_uuid(Uuid::from_u128(value)).unwrap()
}
fn attempt_id(value: u128) -> DeliveryAttemptId {
    DeliveryAttemptId::from_uuid(Uuid::from_u128(value)).unwrap()
}
fn debug(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}
