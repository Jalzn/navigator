use std::future::Future;

pub const DRIVER_CONTRACT_SPECIFICATIONS: &[&str] = &[
    "NAV-DRIVER-CAP-001",
    "NAV-DRIVER-IDENTITY-001",
    "NAV-DRIVER-ACCEPTANCE-001",
    "NAV-DRIVER-LIFECYCLE-001",
    "NAV-DRIVER-OWNERSHIP-001",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityObservation {
    pub id: String,
    pub version: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DriverDescription {
    pub protocol_minimum: u32,
    pub protocol_maximum: u32,
    pub capabilities: Vec<CapabilityObservation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstanceBinding {
    pub driver: u128,
    pub session: u128,
    pub participant: u128,
    pub launch_attempt: u128,
    pub instance: u128,
    pub ownership_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstanceObservation {
    Starting,
    Ready,
    Idle,
    Busy,
    Disconnected,
    Stopped,
    Failed,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptanceObservation {
    Accepted,
    NotAccepted,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverErrorKind {
    Authentication,
    Conflict,
    Unsupported,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopObservation {
    Confirmed,
    AlreadyStopped,
    Uncertain,
    CleanupRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultWindow {
    None,
    CrashBeforeAcceptance,
    CrashAfterDurableAcceptance,
    CrashAfterVolatileReceipt,
}

pub trait DriverSubject {
    fn describe(
        &mut self,
    ) -> impl Future<Output = Result<DriverDescription, DriverErrorKind>> + Send;
    fn start(
        &mut self,
        participant: u128,
        launch_attempt: u128,
        session: u128,
        ownership_epoch: u64,
        required_capabilities: Vec<CapabilityObservation>,
    ) -> impl Future<Output = Result<InstanceBinding, DriverErrorKind>> + Send;
    fn inspect(
        &mut self,
        instance: InstanceBinding,
    ) -> impl Future<Output = Result<InstanceObservation, DriverErrorKind>> + Send;
    fn deliver(
        &mut self,
        instance: InstanceBinding,
        message: u128,
        operation: u128,
        payload: Vec<u8>,
    ) -> impl Future<Output = Result<AcceptanceObservation, DriverErrorKind>> + Send;
    fn acceptance(
        &mut self,
        instance: InstanceBinding,
        message: u128,
    ) -> impl Future<Output = Result<AcceptanceObservation, DriverErrorKind>> + Send;
    fn cancel(
        &mut self,
        instance: InstanceBinding,
        operation: u128,
    ) -> impl Future<Output = Result<(), DriverErrorKind>> + Send;
    fn stop(
        &mut self,
        instance: InstanceBinding,
    ) -> impl Future<Output = Result<StopObservation, DriverErrorKind>> + Send;
    fn native_delivery_count(
        &mut self,
    ) -> impl Future<Output = Result<u64, DriverErrorKind>> + Send;
    fn native_cancel_count(&mut self) -> impl Future<Output = Result<u64, DriverErrorKind>> + Send;
}

pub trait FaultDriverHarness {
    type Subject: DriverSubject;

    fn launch(
        &mut self,
        fault: FaultWindow,
    ) -> impl Future<Output = Result<Self::Subject, DriverErrorKind>> + Send;
    fn restart(
        &mut self,
        fault: FaultWindow,
    ) -> impl Future<Output = Result<Self::Subject, DriverErrorKind>> + Send;
    fn disconnect_owner(&mut self) -> impl Future<Output = Result<(), DriverErrorKind>> + Send;
    fn deliver_after_owner_disconnect(
        &mut self,
    ) -> impl Future<Output = Result<AcceptanceObservation, DriverErrorKind>> + Send;
    fn wait_for_exit_within(
        &mut self,
        milliseconds: u64,
    ) -> impl Future<Output = Result<bool, DriverErrorKind>> + Send;
}

pub trait CapabilityLaunchHarness {
    fn native_process_count(&self) -> u64;
    fn start_requiring(
        &mut self,
        capability: CapabilityObservation,
    ) -> impl Future<Output = Result<(), DriverErrorKind>> + Send;
}

pub async fn assert_driver_contract<S: DriverSubject>(subject: &mut S) -> Result<(), String> {
    let description = subject
        .describe()
        .await
        .map_err(|value| phase_error("describe", value))?;
    ensure(
        description.protocol_minimum <= 1 && description.protocol_maximum >= 1,
        "NAV-DRIVER-CAP-001 protocol v1 is not supported",
    )?;
    let binding = subject
        .start(10, 20, 5, 1, Vec::new())
        .await
        .map_err(|value| phase_error("start", value))?;
    ensure(
        binding.driver != 0
            && binding.session == 5
            && binding.participant == 10
            && binding.launch_attempt == 20
            && binding.instance != 0
            && binding.ownership_epoch == 1,
        "NAV-DRIVER-IDENTITY-001 start changed Navigator-assigned identity",
    )?;
    ensure(
        matches!(
            subject.inspect(binding).await.map_err(error)?,
            InstanceObservation::Ready | InstanceObservation::Idle
        ),
        "NAV-DRIVER-LIFECYCLE-001 Instance was not ready after start",
    )?;

    for (dimension, forged) in forged_bindings(binding) {
        if !matches!(
            subject.inspect(forged).await,
            Err(DriverErrorKind::Authentication | DriverErrorKind::Conflict)
        ) {
            return Err(format!(
                "NAV-DRIVER-IDENTITY-001 inspect(forged_{dimension}) did not return Authentication/Conflict"
            ));
        }
    }
    ensure(
        subject
            .deliver(binding, 39, 40, b"cancel-target".to_vec())
            .await
            .map_err(|value| phase_error("deliver(cancel_target)", value))?
            == AcceptanceObservation::Accepted,
        "NAV-DRIVER-LIFECYCLE-001 cancellation target was not accepted",
    )?;
    let cancels_before = subject.native_cancel_count().await.map_err(error)?;
    subject
        .cancel(binding, 40)
        .await
        .map_err(|value| phase_error("cancel1", value))?;
    let cancels = subject.native_cancel_count().await.map_err(error)?;
    ensure(
        cancels == cancels_before.saturating_add(1),
        "NAV-DRIVER-LIFECYCLE-001 first cancellation lacked exactly one native effect",
    )?;
    subject
        .cancel(binding, 40)
        .await
        .map_err(|value| phase_error("cancel2(replay)", value))?;
    ensure(
        subject.native_cancel_count().await.map_err(error)? == cancels,
        "NAV-DRIVER-LIFECYCLE-001 cancellation replay reached the Executor twice",
    )?;
    ensure(
        subject
            .stop(binding)
            .await
            .map_err(|value| phase_error("stop1", value))?
            == StopObservation::Confirmed,
        "NAV-DRIVER-LIFECYCLE-001 stop was not confirmed",
    )?;
    ensure(
        subject
            .stop(binding)
            .await
            .map_err(|value| phase_error("stop2(replay)", value))?
            == StopObservation::AlreadyStopped,
        "NAV-DRIVER-LIFECYCLE-001 stop replay was not idempotent",
    )?;
    ensure(
        matches!(
            subject.inspect(binding).await,
            Ok(InstanceObservation::Stopped) | Err(DriverErrorKind::Unavailable)
        ),
        "NAV-DRIVER-LIFECYCLE-001 Instance remained inspectable as active after Stop",
    )
}

pub async fn assert_durable_acceptance_contract<S: DriverSubject>(
    subject: &mut S,
) -> Result<(), String> {
    let description = subject
        .describe()
        .await
        .map_err(|value| phase_error("describe", value))?;
    ensure(
        description
            .capabilities
            .iter()
            .any(|item| item.id == "durable.acceptance" && item.version >= 1),
        "NAV-DRIVER-CAP-001 subject does not claim durable acceptance",
    )?;
    let binding = subject
        .start(
            11,
            21,
            6,
            1,
            vec![CapabilityObservation {
                id: "durable.acceptance".into(),
                version: 1,
            }],
        )
        .await
        .map_err(|value| phase_error("start", value))?;
    let accepted = subject
        .deliver(binding, 30, 40, b"semantic-input".to_vec())
        .await
        .map_err(|value| phase_error("deliver.first", value))?;
    ensure(
        accepted == AcceptanceObservation::Accepted,
        "NAV-DRIVER-ACCEPTANCE-001 durable delivery was not accepted",
    )?;
    ensure(
        subject
            .acceptance(binding, 30)
            .await
            .map_err(|value| phase_error("acceptance.first", value))?
            == AcceptanceObservation::Accepted,
        "NAV-DRIVER-ACCEPTANCE-001 accepted identity could not be reconciled",
    )?;
    let deliveries = subject
        .native_delivery_count()
        .await
        .map_err(|value| phase_error("native_delivery_count.first", value))?;
    ensure(
        subject
            .deliver(binding, 30, 40, b"semantic-input".to_vec())
            .await
            .map_err(|value| phase_error("deliver.replay", value))?
            == AcceptanceObservation::Accepted,
        "NAV-DRIVER-ACCEPTANCE-001 equivalent delivery replay changed outcome",
    )?;
    ensure(
        subject
            .native_delivery_count()
            .await
            .map_err(|value| phase_error("native_delivery_count.replay", value))?
            == deliveries,
        "NAV-DRIVER-ACCEPTANCE-001 replay injected the Message twice",
    )?;
    ensure(
        subject
            .deliver(binding, 30, 40, b"different-input".to_vec())
            .await
            == Err(DriverErrorKind::Conflict),
        "NAV-DRIVER-ACCEPTANCE-001 Message identity accepted different semantics",
    )?;
    ensure(
        subject
            .native_delivery_count()
            .await
            .map_err(|value| phase_error("native_delivery_count.conflict", value))?
            == deliveries,
        "NAV-DRIVER-ACCEPTANCE-001 conflicting replay caused an effect",
    )?;

    Ok(())
}

pub async fn assert_missing_capability_prevents_launch<H: CapabilityLaunchHarness>(
    harness: &mut H,
) -> Result<(), String> {
    let before = harness.native_process_count();
    ensure(
        harness
            .start_requiring(CapabilityObservation {
                id: "capability.absent".into(),
                version: 1,
            })
            .await
            == Err(DriverErrorKind::Unsupported),
        "NAV-DRIVER-CAP-001 missing capability did not fail",
    )?;
    ensure(
        harness.native_process_count() == before,
        "NAV-DRIVER-CAP-001 missing capability created an external process",
    )
}

pub async fn assert_driver_fault_windows<H: FaultDriverHarness>(
    harness: &mut H,
) -> Result<(), String> {
    let mut before = harness
        .launch(FaultWindow::CrashBeforeAcceptance)
        .await
        .map_err(error)?;
    let binding = before
        .start(10, 21, 5, 1, Vec::new())
        .await
        .map_err(error)?;
    ensure(
        before.deliver(binding, 31, 41, b"before".to_vec()).await
            == Err(DriverErrorKind::Unavailable),
        "NAV-DRIVER-ACCEPTANCE-001 pre-acceptance crash was not observed",
    )?;
    let mut before = harness.restart(FaultWindow::None).await.map_err(error)?;
    ensure(
        before.acceptance(binding, 31).await.map_err(error)? == AcceptanceObservation::NotAccepted,
        "NAV-DRIVER-ACCEPTANCE-001 pre-boundary crash left false acceptance",
    )?;

    let mut after = harness
        .restart(FaultWindow::CrashAfterDurableAcceptance)
        .await
        .map_err(error)?;
    ensure(
        after.deliver(binding, 32, 42, b"after".to_vec()).await
            == Err(DriverErrorKind::Unavailable),
        "NAV-DRIVER-ACCEPTANCE-001 post-acceptance crash was not observed",
    )?;
    let mut after = harness.restart(FaultWindow::None).await.map_err(error)?;
    ensure(
        after.acceptance(binding, 32).await.map_err(error)? == AcceptanceObservation::Accepted,
        "NAV-DRIVER-ACCEPTANCE-001 durable acceptance was lost across restart",
    )?;
    let count = after.native_delivery_count().await.map_err(error)?;
    ensure(
        after
            .deliver(binding, 32, 42, b"after".to_vec())
            .await
            .map_err(error)?
            == AcceptanceObservation::Accepted,
        "NAV-DRIVER-ACCEPTANCE-001 accepted delivery could not be replayed",
    )?;
    ensure(
        after.native_delivery_count().await.map_err(error)? == count,
        "NAV-DRIVER-ACCEPTANCE-001 restart replay duplicated native injection",
    )?;

    let mut volatile = harness
        .restart(FaultWindow::CrashAfterVolatileReceipt)
        .await
        .map_err(error)?;
    ensure(
        volatile
            .deliver(binding, 33, 43, b"volatile".to_vec())
            .await
            == Err(DriverErrorKind::Unavailable),
        "NAV-DRIVER-ACCEPTANCE-001 volatile crash was not observed",
    )?;
    let mut volatile = harness.restart(FaultWindow::None).await.map_err(error)?;
    ensure(
        matches!(
            volatile.acceptance(binding, 33).await.map_err(error)?,
            AcceptanceObservation::Unknown | AcceptanceObservation::NotAccepted
        ),
        "NAV-DRIVER-ACCEPTANCE-001 volatile receipt became false durable acceptance",
    )?;

    harness.disconnect_owner().await.map_err(error)?;
    ensure(
        harness.deliver_after_owner_disconnect().await == Err(DriverErrorKind::Unavailable),
        "NAV-DRIVER-OWNERSHIP-001 Driver admitted work after ownership loss",
    )?;
    ensure(
        harness.wait_for_exit_within(1_000).await.map_err(error)?,
        "NAV-DRIVER-OWNERSHIP-001 Driver did not exit within the ownership-loss bound",
    )
}

fn forged_bindings(binding: InstanceBinding) -> [(&'static str, InstanceBinding); 6] {
    [
        (
            "driver",
            InstanceBinding {
                driver: binding.driver.wrapping_add(1),
                ..binding
            },
        ),
        (
            "session",
            InstanceBinding {
                session: binding.session.wrapping_add(1),
                ..binding
            },
        ),
        (
            "participant",
            InstanceBinding {
                participant: binding.participant.wrapping_add(1),
                ..binding
            },
        ),
        (
            "launch_attempt",
            InstanceBinding {
                launch_attempt: binding.launch_attempt.wrapping_add(1),
                ..binding
            },
        ),
        (
            "instance",
            InstanceBinding {
                instance: binding.instance.wrapping_add(1),
                ..binding
            },
        ),
        (
            "ownership_epoch",
            InstanceBinding {
                ownership_epoch: binding.ownership_epoch.wrapping_add(1),
                ..binding
            },
        ),
    ]
}

fn ensure(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn error(error: DriverErrorKind) -> String {
    format!("Driver failed unexpectedly: {error:?}")
}

fn phase_error(phase: &str, error: DriverErrorKind) -> String {
    format!("Driver {phase} failed unexpectedly: {error:?}")
}

#[cfg(test)]
mod tests {
    use super::{AcceptanceObservation, DriverErrorKind};
    use std::collections::BTreeMap;

    trait AcceptanceSubject {
        fn deliver(
            &mut self,
            message: u8,
            payload: u8,
        ) -> Result<AcceptanceObservation, DriverErrorKind>;
        fn effects(&self) -> usize;
    }

    #[derive(Default)]
    struct DurableDeduplicating(BTreeMap<u8, u8>);

    impl AcceptanceSubject for DurableDeduplicating {
        fn deliver(
            &mut self,
            message: u8,
            payload: u8,
        ) -> Result<AcceptanceObservation, DriverErrorKind> {
            match self.0.get(&message) {
                Some(existing) if *existing != payload => Err(DriverErrorKind::Conflict),
                Some(_) => Ok(AcceptanceObservation::Accepted),
                None => {
                    self.0.insert(message, payload);
                    Ok(AcceptanceObservation::Accepted)
                }
            }
        }

        fn effects(&self) -> usize {
            self.0.len()
        }
    }

    #[derive(Default)]
    struct DuplicateInjecting(Vec<(u8, u8)>);

    impl AcceptanceSubject for DuplicateInjecting {
        fn deliver(
            &mut self,
            message: u8,
            payload: u8,
        ) -> Result<AcceptanceObservation, DriverErrorKind> {
            self.0.push((message, payload));
            Ok(AcceptanceObservation::Accepted)
        }

        fn effects(&self) -> usize {
            self.0.len()
        }
    }

    fn deduplication_oracle(subject: &mut impl AcceptanceSubject) -> Result<(), &'static str> {
        let first = subject
            .deliver(1, 7)
            .map_err(|_| "initial delivery failed")?;
        let replay = subject.deliver(1, 7).map_err(|_| "replay failed")?;
        if first != AcceptanceObservation::Accepted
            || replay != AcceptanceObservation::Accepted
            || subject.effects() != 1
        {
            return Err("NAV-DRIVER-ACCEPTANCE-001 duplicate injection");
        }
        Ok(())
    }

    #[test]
    fn acceptance_oracle_rejects_duplicate_injection_mutant() {
        deduplication_oracle(&mut DurableDeduplicating::default()).expect("reference conforms");
        assert!(deduplication_oracle(&mut DuplicateInjecting::default()).is_err());
    }
}
