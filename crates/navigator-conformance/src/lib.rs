//! Semantic reference models and reusable conformance assertions.
pub mod effect_journal;
pub mod tool_store;

use navigator_domain::{
    Authority, Capability, Clock, FencingEpoch, IdentitySource, MonotonicInstant, OperationState,
};
use serde::Serialize;
use std::{cell::Cell, collections::BTreeSet};
use time::{Duration, OffsetDateTime};

pub mod driver;
pub mod instance_store;
pub mod mailbox_store;
pub mod operation_store;
pub mod store;
pub mod topology_store;

pub struct FakeClock {
    wall: Cell<OffsetDateTime>,
    ticks: Cell<u64>,
}

impl FakeClock {
    #[must_use]
    pub const fn new(wall: OffsetDateTime, ticks: u64) -> Self {
        Self {
            wall: Cell::new(wall),
            ticks: Cell::new(ticks),
        }
    }

    pub fn advance(&self, duration: Duration, ticks: u64) {
        self.wall.set(self.wall.get() + duration);
        self.ticks.set(self.ticks.get() + ticks);
    }

    pub fn regress_wall(&self, duration: Duration) {
        self.wall.set(self.wall.get() - duration);
    }
}

impl Clock for FakeClock {
    fn wall_now(&self) -> OffsetDateTime {
        self.wall.get()
    }

    fn monotonic_now(&self) -> MonotonicInstant {
        MonotonicInstant::from_ticks(self.ticks.get())
    }
}

pub struct DeterministicIds {
    next: u128,
}

impl DeterministicIds {
    #[must_use]
    pub const fn new(first: u128) -> Self {
        Self { next: first }
    }
}

impl IdentitySource for DeterministicIds {
    fn next_uuid(&mut self) -> uuid::Uuid {
        let value = uuid::Uuid::from_u128(self.next);
        self.next = self
            .next
            .checked_add(1)
            .expect("test identity space exhausted");
        value
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultInjected(pub Capability);

#[derive(Default)]
pub struct FaultInjector {
    armed: BTreeSet<Capability>,
    observed: Vec<Capability>,
}

impl FaultInjector {
    #[must_use]
    pub fn armed(points: impl IntoIterator<Item = Capability>) -> Self {
        Self {
            armed: points.into_iter().collect(),
            observed: Vec::new(),
        }
    }

    pub fn hit(&mut self, point: Capability) -> Result<(), FaultInjected> {
        self.observed.push(point.clone());
        if self.armed.remove(&point) {
            Err(FaultInjected(point))
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn observed(&self) -> &[Capability] {
        &self.observed
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceOutcome {
    Passed,
    MutantRejected,
    Failed,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct EvidenceRecord<'a> {
    pub invariant: &'a str,
    pub specification: &'a str,
    pub subject: &'a str,
    pub incorrect_behavior: &'a str,
    pub outcome: EvidenceOutcome,
    pub seed: Option<u64>,
}

impl EvidenceRecord<'_> {
    #[must_use]
    pub fn human(&self) -> String {
        format!(
            "{} [{}]: {:?} ({}, rejects: {})",
            self.invariant, self.specification, self.outcome, self.subject, self.incorrect_behavior
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationCommand {
    BeginStart,
    ReportRunning,
    Wait,
    Resume,
    RequestCancel,
    ReportSuccess,
    ReportFailure,
    ReportCancelled,
    ReportBlocked,
    ReportUncertain,
    ObserveIdle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observation {
    State(OperationState),
    Rejected,
}

pub trait OperationSubject {
    fn state(&self) -> OperationState;
    fn execute(&mut self, command: OperationCommand) -> Observation;
}

pub trait AuthoritySubject {
    fn effective(&self, parent: &Authority, ceiling: &Authority) -> Authority;
}

pub fn assert_authority_decreases<S: AuthoritySubject>(
    subject: &S,
    parent: &Authority,
    ceiling: &Authority,
) -> Result<(), String> {
    let actual = subject.effective(parent, ceiling);
    let expected = Authority::new(
        parent
            .capabilities()
            .filter(|capability| ceiling.contains(capability))
            .cloned(),
    );
    if actual != expected {
        return Err("NAV-AUTH-001 delegated authority is not the required intersection".into());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FencedSnapshot {
    pub epoch: FencingEpoch,
    pub revision: u64,
    pub value: u64,
    pub events: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaleEpoch;

pub trait FencedWriteSubject {
    fn snapshot(&self) -> FencedSnapshot;
    fn takeover(&mut self, epoch: FencingEpoch);
    fn write(&mut self, epoch: FencingEpoch, value: u64) -> Result<(), StaleEpoch>;
}

pub fn assert_stale_epoch_is_fenced<S: FencedWriteSubject>(
    subject: &mut S,
    old: FencingEpoch,
    current: FencingEpoch,
) -> Result<(), String> {
    subject.takeover(current);
    let before = subject.snapshot();
    if before.epoch != current {
        return Err("NAV-LEASE-001 takeover did not publish the current epoch".into());
    }
    if subject.write(old, 41).is_ok() {
        return Err("NAV-LEASE-001 stale epoch write was accepted".into());
    }
    if subject.snapshot() != before {
        return Err("NAV-LEASE-001 rejected write changed state or emitted an event".into());
    }
    subject
        .write(current, 42)
        .map_err(|StaleEpoch| "NAV-LEASE-001 current owner could not write".to_owned())?;
    let after = subject.snapshot();
    if after.value != 42
        || after.revision != before.revision + 1
        || after.events != before.events + 1
    {
        return Err("NAV-LEASE-001 accepted write did not commit one fact".into());
    }
    Ok(())
}

pub fn model_step(state: OperationState, command: OperationCommand) -> Observation {
    use OperationCommand::{
        BeginStart, ReportBlocked, ReportCancelled, ReportFailure, ReportRunning, ReportSuccess,
        ReportUncertain, RequestCancel, Resume, Wait,
    };
    use OperationState::{
        Blocked, Cancelled, Cancelling, Failed, Queued, Running, Starting, Succeeded, Uncertain,
        Waiting,
    };

    let next = match (state, command) {
        (Queued, BeginStart) => Some(Starting),
        (Starting, ReportRunning) | (Waiting, Resume) => Some(Running),
        (Running, Wait) => Some(Waiting),
        (Queued | Starting | Running | Waiting, RequestCancel) => Some(Cancelling),
        (Queued | Cancelling, ReportCancelled) => Some(Cancelled),
        (Queued | Starting | Running | Waiting | Cancelling, ReportFailure) => Some(Failed),
        (Running, ReportSuccess) => Some(Succeeded),
        (Running | Waiting, ReportBlocked) => Some(Blocked),
        (Starting | Running | Waiting | Cancelling, ReportUncertain) => Some(Uncertain),
        _ => None,
    };
    next.map_or(Observation::Rejected, Observation::State)
}

pub fn assert_operation_trace<S: OperationSubject>(
    subject: &mut S,
    commands: &[OperationCommand],
) -> Result<(), String> {
    let mut expected = OperationState::Queued;
    if subject.state() != expected {
        return Err(format!(
            "NAV-OP-000 initial state mismatch: expected {expected:?}, got {:?}",
            subject.state()
        ));
    }

    for (index, command) in commands.iter().copied().enumerate() {
        let expected_observation = model_step(expected, command);
        let actual = subject.execute(command);
        if actual != expected_observation {
            return Err(format!(
                "NAV-OP semantic mismatch at step {index}: state={expected:?}, command={command:?}, expected={expected_observation:?}, actual={actual:?}"
            ));
        }
        if let Observation::State(next) = expected_observation {
            expected = next;
        }
        if subject.state() != expected {
            return Err(format!(
                "NAV-OP state mismatch at step {index}: expected={expected:?}, actual={:?}",
                subject.state()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use navigator_domain::{
        Authority, Capability, Clock, EffectClass, EffectPhase, FencingEpoch, Operation,
        OperationAction, OperationId, OperationState, ParticipantId, RecoveryClass, RequestId,
    };
    use proptest::prelude::*;

    use super::{
        AuthoritySubject, DeterministicIds, EvidenceOutcome, EvidenceRecord, FakeClock,
        FaultInjector, FencedSnapshot, FencedWriteSubject, Observation, OperationCommand,
        OperationSubject, assert_authority_decreases, assert_operation_trace,
        assert_stale_epoch_is_fenced,
    };

    struct DomainSubject(Operation);

    impl DomainSubject {
        fn new() -> Self {
            Self(Operation::queued(
                OperationId::from_uuid(uuid::Uuid::from_u128(1)).unwrap(),
                ParticipantId::from_uuid(uuid::Uuid::from_u128(2)).unwrap(),
                RequestId::from_uuid(uuid::Uuid::from_u128(3)).unwrap(),
            ))
        }
    }

    impl OperationSubject for DomainSubject {
        fn state(&self) -> OperationState {
            self.0.state()
        }

        fn execute(&mut self, command: OperationCommand) -> Observation {
            let action = match command {
                OperationCommand::BeginStart => OperationAction::BeginStart,
                OperationCommand::ReportRunning => OperationAction::ReportRunning,
                OperationCommand::Wait => OperationAction::Wait,
                OperationCommand::Resume => OperationAction::Resume,
                OperationCommand::RequestCancel => OperationAction::RequestCancel,
                OperationCommand::ReportSuccess => OperationAction::ReportSuccess,
                OperationCommand::ReportFailure => OperationAction::ReportFailure,
                OperationCommand::ReportCancelled => OperationAction::ReportCancelled,
                OperationCommand::ReportBlocked => OperationAction::ReportBlocked,
                OperationCommand::ReportUncertain => OperationAction::ReportUncertain,
                OperationCommand::ObserveIdle => OperationAction::ObserveIdle,
            };
            self.0.apply(action).map_or(Observation::Rejected, |()| {
                Observation::State(self.0.state())
            })
        }
    }

    struct IdleMeansSuccess(OperationState);

    impl OperationSubject for IdleMeansSuccess {
        fn state(&self) -> OperationState {
            self.0
        }

        fn execute(&mut self, command: OperationCommand) -> Observation {
            if command == OperationCommand::ObserveIdle {
                self.0 = OperationState::Succeeded;
                Observation::State(self.0)
            } else {
                Observation::Rejected
            }
        }
    }

    struct IntersectionAuthority;

    impl AuthoritySubject for IntersectionAuthority {
        fn effective(&self, parent: &Authority, ceiling: &Authority) -> Authority {
            parent.intersect(ceiling)
        }
    }

    struct UnionAuthority;

    impl AuthoritySubject for UnionAuthority {
        fn effective(&self, parent: &Authority, ceiling: &Authority) -> Authority {
            let capabilities = [parent, ceiling].into_iter().flat_map(|authority| {
                ["fs.read", "fs.write", "process.shell"]
                    .into_iter()
                    .filter_map(|name| {
                        let capability = Capability::new(name).unwrap();
                        authority.contains(&capability).then_some(capability)
                    })
            });
            Authority::new(capabilities)
        }
    }

    struct CorrectFencedStore(FencedSnapshot);

    impl FencedWriteSubject for CorrectFencedStore {
        fn snapshot(&self) -> FencedSnapshot {
            self.0
        }

        fn takeover(&mut self, epoch: FencingEpoch) {
            self.0.epoch = epoch;
        }

        fn write(&mut self, epoch: FencingEpoch, value: u64) -> Result<(), super::StaleEpoch> {
            if !epoch.is_current(self.0.epoch) {
                return Err(super::StaleEpoch);
            }
            self.0.value = value;
            self.0.revision += 1;
            self.0.events += 1;
            Ok(())
        }
    }

    struct IgnoresFence(CorrectFencedStore);

    impl FencedWriteSubject for IgnoresFence {
        fn snapshot(&self) -> FencedSnapshot {
            self.0.snapshot()
        }

        fn takeover(&mut self, epoch: FencingEpoch) {
            self.0.takeover(epoch);
        }

        fn write(&mut self, _epoch: FencingEpoch, value: u64) -> Result<(), super::StaleEpoch> {
            self.0.0.value = value;
            self.0.0.revision += 1;
            self.0.0.events += 1;
            Ok(())
        }
    }

    #[test]
    fn nav_op_005_idle_never_implies_success() {
        let failure = assert_operation_trace(
            &mut IdleMeansSuccess(OperationState::Queued),
            &[OperationCommand::ObserveIdle],
        );
        assert!(
            failure
                .expect_err("the semantic harness must kill idle-means-success mutation")
                .contains("semantic mismatch")
        );
    }

    #[test]
    fn canonical_success_trace_conforms() {
        assert_operation_trace(
            &mut DomainSubject::new(),
            &[
                OperationCommand::BeginStart,
                OperationCommand::ReportRunning,
                OperationCommand::ObserveIdle,
                OperationCommand::ReportSuccess,
            ],
        )
        .expect("canonical trace must conform");
    }

    #[test]
    fn nav_recovery_001_started_non_idempotent_effect_is_uncertain() {
        for effect in [
            EffectClass::Transactional,
            EffectClass::NonIdempotent,
            EffectClass::Unknown,
        ] {
            assert_eq!(
                RecoveryClass::for_effect(effect, EffectPhase::Started),
                RecoveryClass::EffectUncertain
            );
        }
    }

    #[test]
    fn fake_clock_separates_wall_regression_from_monotonic_progress() {
        let clock = FakeClock::new(time::macros::datetime!(2026-01-01 0:00 UTC), 10);
        clock.advance(time::Duration::seconds(5), 5);
        clock.regress_wall(time::Duration::seconds(20));
        assert_eq!(clock.monotonic_now().ticks(), 15);
        assert_eq!(
            clock.wall_now(),
            time::macros::datetime!(2025-12-31 23:59:45 UTC)
        );
    }

    #[test]
    fn deterministic_identity_and_named_faults_are_reproducible() {
        let mut ids = DeterministicIds::new(10);
        let first = ParticipantId::generate(&mut ids).unwrap();
        let second = ParticipantId::generate(&mut ids).unwrap();
        assert_eq!(first.as_uuid(), uuid::Uuid::from_u128(10));
        assert_eq!(second.as_uuid(), uuid::Uuid::from_u128(11));

        let point = Capability::new("delivery.after_lease").unwrap();
        let mut faults = FaultInjector::armed([point.clone()]);
        assert_eq!(
            faults.hit(point.clone()),
            Err(super::FaultInjected(point.clone()))
        );
        assert!(faults.hit(point.clone()).is_ok());
        assert_eq!(faults.observed(), &[point.clone(), point]);
    }

    #[test]
    fn evidence_has_machine_and_human_representations() {
        let evidence = EvidenceRecord {
            invariant: "NAV-OP-005",
            specification: "docs/principles.md#acceptance-is-not-completion",
            subject: "IdleMeansSuccess",
            incorrect_behavior: "idle inferred as success",
            outcome: EvidenceOutcome::MutantRejected,
            seed: Some(42),
        };
        let json = serde_json::to_string(&evidence).unwrap();
        assert!(json.contains("\"outcome\":\"mutant_rejected\""));
        assert!(evidence.human().contains("NAV-OP-005"));
    }

    #[test]
    fn nav_authority_001_effective_authority_is_intersection() {
        let read = Capability::new("fs.read").unwrap();
        let write = Capability::new("fs.write").unwrap();
        let shell = Capability::new("process.shell").unwrap();
        let parent = Authority::new([read.clone(), write.clone()]);
        let ceiling = Authority::new([read.clone(), shell.clone()]);

        assert_authority_decreases(&IntersectionAuthority, &parent, &ceiling).unwrap();
        assert!(
            assert_authority_decreases(&UnionAuthority, &parent, &ceiling)
                .expect_err("suite must kill union implementation")
                .contains("NAV-AUTH-001")
        );
    }

    #[test]
    fn nav_lease_001_stale_epoch_cannot_authorize_write() {
        let old = FencingEpoch::new(7).unwrap();
        let current = FencingEpoch::new(8).unwrap();
        let initial = FencedSnapshot {
            epoch: old,
            revision: 1,
            value: 0,
            events: 0,
        };
        assert_stale_epoch_is_fenced(&mut CorrectFencedStore(initial), old, current).unwrap();
        assert!(
            assert_stale_epoch_is_fenced(
                &mut IgnoresFence(CorrectFencedStore(initial)),
                old,
                current
            )
            .expect_err("suite must kill missing-fence implementation")
            .contains("NAV-LEASE-001")
        );
    }

    proptest! {
        #[test]
        fn generated_operation_traces_match_reference_model(
            commands in proptest::collection::vec(any_operation_command(), 0..200)
        ) {
            prop_assert!(
                assert_operation_trace(&mut DomainSubject::new(), &commands).is_ok()
            );
        }

        #[test]
        fn terminal_state_never_changes(
            terminal in prop_oneof![
                Just(OperationState::Succeeded),
                Just(OperationState::Failed),
                Just(OperationState::Cancelled),
                Just(OperationState::Blocked),
                Just(OperationState::Uncertain),
            ],
            action in any_operation_action(),
        ) {
            let mut operation = Operation::queued(
                OperationId::from_uuid(uuid::Uuid::from_u128(1)).unwrap(),
                ParticipantId::from_uuid(uuid::Uuid::from_u128(2)).unwrap(),
                RequestId::from_uuid(uuid::Uuid::from_u128(3)).unwrap(),
            );
            reach_terminal(&mut operation, terminal);
            prop_assert!(operation.apply(action).is_err());
            prop_assert_eq!(operation.state(), terminal);
        }
    }

    fn any_operation_command() -> impl Strategy<Value = OperationCommand> {
        prop_oneof![
            Just(OperationCommand::BeginStart),
            Just(OperationCommand::ReportRunning),
            Just(OperationCommand::Wait),
            Just(OperationCommand::Resume),
            Just(OperationCommand::RequestCancel),
            Just(OperationCommand::ReportSuccess),
            Just(OperationCommand::ReportFailure),
            Just(OperationCommand::ReportCancelled),
            Just(OperationCommand::ReportBlocked),
            Just(OperationCommand::ReportUncertain),
            Just(OperationCommand::ObserveIdle),
        ]
    }

    fn reach_terminal(operation: &mut Operation, terminal: OperationState) {
        use OperationAction::{
            BeginStart, ReportBlocked, ReportCancelled, ReportFailure, ReportRunning,
            ReportSuccess, ReportUncertain,
        };
        use OperationState::{Blocked, Cancelled, Failed, Succeeded, Uncertain};

        match terminal {
            Cancelled => {
                operation.apply(ReportCancelled).unwrap();
            }
            Failed => {
                operation.apply(ReportFailure).unwrap();
            }
            Succeeded | Blocked => {
                operation.apply(BeginStart).unwrap();
                operation.apply(ReportRunning).unwrap();
                operation
                    .apply(if terminal == Succeeded {
                        ReportSuccess
                    } else {
                        ReportBlocked
                    })
                    .unwrap();
            }
            Uncertain => {
                operation.apply(BeginStart).unwrap();
                operation.apply(ReportUncertain).unwrap();
            }
            _ => unreachable!("strategy generates terminal states only"),
        }
    }

    fn any_operation_action() -> impl Strategy<Value = OperationAction> {
        prop_oneof![
            Just(OperationAction::BeginStart),
            Just(OperationAction::ReportRunning),
            Just(OperationAction::Wait),
            Just(OperationAction::Resume),
            Just(OperationAction::RequestCancel),
            Just(OperationAction::ReportSuccess),
            Just(OperationAction::ReportFailure),
            Just(OperationAction::ReportCancelled),
            Just(OperationAction::ReportBlocked),
            Just(OperationAction::ReportUncertain),
            Just(OperationAction::ObserveIdle),
        ]
    }
}
