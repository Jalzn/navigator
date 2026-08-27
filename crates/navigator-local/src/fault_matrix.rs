//! Stable semantic names for external-effect fault boundaries.
//!
//! These names are deliberately data, rather than test-private strings.  The
//! release fault-matrix gate compares this source declaration bidirectionally
//! with the reviewed manifest, so adding or removing an effect boundary cannot
//! silently reduce crash coverage.

#[cfg_attr(
    not(test),
    allow(dead_code, reason = "release gate reads this source-owned inventory")
)]
pub const EXTERNAL_EFFECT_FAULT_POINTS: &[&str] = &[
    "launch.external.before_call",
    "launch.external.after_call",
    "launch.external.before_identity_proof",
    "launch.external.after_identity_proof",
    "delivery.external.before_call",
    "delivery.external.after_call",
    "delivery.external.before_acceptance_proof",
    "delivery.external.after_acceptance_proof",
    "tool.external.before_call",
    "tool.external.after_call",
    "tool.external.before_result_proof",
    "tool.external.after_result_proof",
    "report.external.before_call",
    "report.external.after_call",
    "report.external.before_correlation_proof",
    "report.external.after_correlation_proof",
    "cancellation.external.before_call",
    "cancellation.external.after_call",
    "cancellation.external.before_stop_proof",
    "cancellation.external.after_stop_proof",
    "artifact.external.before_call",
    "artifact.external.after_call",
    "artifact.external.before_metadata_proof",
    "artifact.external.after_metadata_proof",
    "approval.external.before_call",
    "approval.external.after_call",
    "approval.external.before_effect_proof",
    "approval.external.after_effect_proof",
    "shutdown.external.before_call",
    "shutdown.external.after_call",
    "shutdown.external.before_identity_proof",
    "shutdown.external.after_identity_proof",
];

/// Test-only subprocess fault injector placed at semantic external-effect
/// boundaries. The environment variable is intentionally honored only by test
/// builds, so production processes cannot acquire a hidden abort surface.
#[inline]
pub(crate) fn external_fault_at(point: &'static str) {
    #[cfg(any(test, feature = "fault-injection"))]
    if std::env::var_os("NAVIGATOR_EXTERNAL_FAULT_POINT").is_some_and(|selected| selected == point)
    {
        if let Some(path) = std::env::var_os("NAVIGATOR_EXTERNAL_FAULT_OBSERVATION") {
            std::fs::write(path, point.as_bytes())
                .expect("external fault observation marker must be writable");
        }
        std::process::abort();
    }
    #[cfg(not(any(test, feature = "fault-injection")))]
    let _ = point;
}

#[cfg(test)]
mod tests {
    use super::EXTERNAL_EFFECT_FAULT_POINTS;
    use std::collections::BTreeSet;

    #[test]
    fn external_fault_point_names_are_unique_and_closed() {
        let unique = EXTERNAL_EFFECT_FAULT_POINTS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), EXTERNAL_EFFECT_FAULT_POINTS.len());
        assert!(
            EXTERNAL_EFFECT_FAULT_POINTS
                .iter()
                .all(|point| point.contains(".external."))
        );
    }
}
