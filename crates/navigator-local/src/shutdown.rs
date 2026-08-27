use std::{future::Future, time::Duration};

use tokio::time::Instant;

#[derive(Clone, Copy, Debug)]
pub(crate) struct ShutdownDeadline {
    at: Instant,
}

impl ShutdownDeadline {
    pub(crate) fn after(duration: Duration) -> Self {
        Self {
            at: Instant::now() + duration,
        }
    }

    pub(crate) const fn instant(self) -> Instant {
        self.at
    }

    pub(crate) fn remaining(self) -> Duration {
        self.at.saturating_duration_since(Instant::now())
    }

    pub(crate) async fn run<F>(self, future: F) -> Result<F::Output, Elapsed>
    where
        F: Future,
    {
        if self.remaining().is_zero() {
            return Err(Elapsed);
        }
        tokio::time::timeout_at(self.at, future)
            .await
            .map_err(|_| Elapsed)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Elapsed;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::ShutdownDeadline;

    #[tokio::test]
    async fn nested_phases_reuse_one_absolute_deadline() {
        let deadline = ShutdownDeadline::after(Duration::from_secs(10));
        let absolute = deadline.instant();

        deadline
            .run(async { tokio::task::yield_now().await })
            .await
            .expect("ready phase remains within the end-to-end deadline");
        assert_eq!(deadline.instant(), absolute);
        deadline
            .run(async { tokio::task::yield_now().await })
            .await
            .expect("second ready phase remains within the same deadline");
        assert_eq!(deadline.instant(), absolute);
    }

    #[tokio::test]
    async fn exhausted_deadline_does_not_poll_a_new_cleanup_effect() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        let deadline = ShutdownDeadline {
            at: tokio::time::Instant::now(),
        };
        let began = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&began);

        assert!(
            deadline
                .run(async move {
                    observed.store(true, Ordering::Release);
                })
                .await
                .is_err()
        );
        assert!(!began.load(Ordering::Acquire));
    }
}
