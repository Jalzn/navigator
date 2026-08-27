use std::{collections::HashMap, future::Future, sync::Arc};

use thiserror::Error;
use tokio::{
    sync::{Mutex, Notify, oneshot},
    task::JoinHandle,
    time::Instant,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackgroundShutdownOutcome {
    Complete,
    CleanupRequired,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("background task admission is closed")]
pub struct BackgroundTaskClosed;

#[derive(Clone)]
pub struct BackgroundTaskRegistry {
    inner: Arc<Inner>,
}

struct Inner {
    state: Mutex<State>,
    shutdown_complete: Notify,
}

struct State {
    accepting: bool,
    next_id: u64,
    tasks: HashMap<u64, JoinHandle<()>>,
    shutdown_started: bool,
    shutdown_outcome: Option<BackgroundShutdownOutcome>,
    cleanup_required: bool,
}

impl Default for BackgroundTaskRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BackgroundTaskRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    accepting: true,
                    next_id: 0,
                    tasks: HashMap::new(),
                    shutdown_started: false,
                    shutdown_outcome: None,
                    cleanup_required: false,
                }),
                shutdown_complete: Notify::new(),
            }),
        }
    }

    pub async fn close_admission(&self) {
        self.inner.state.lock().await.accepting = false;
    }

    /// Records a durable cleanup failure observed by a background owner. This
    /// bit is sticky so a task that has already exited cannot make shutdown look
    /// clean after failing to release external state.
    pub async fn mark_cleanup_required(&self) {
        self.inner.state.lock().await.cleanup_required = true;
    }

    pub async fn spawn<F>(&self, future: F) -> Result<(), BackgroundTaskClosed>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut state = self.inner.state.lock().await;
        if !state.accepting {
            return Err(BackgroundTaskClosed);
        }
        let id = state.next_id;
        let Some(next_id) = state.next_id.checked_add(1) else {
            state.accepting = false;
            return Err(BackgroundTaskClosed);
        };
        state.next_id = next_id;
        let registry = self.clone();
        let (start, started) = oneshot::channel();
        let handle = tokio::spawn(async move {
            if started.await.is_err() {
                return;
            }
            future.await;
            registry.inner.state.lock().await.tasks.remove(&id);
        });
        state.tasks.insert(id, handle);
        drop(state);
        let _ = start.send(());
        Ok(())
    }

    pub async fn prune_finished(&self) -> usize {
        let mut state = self.inner.state.lock().await;
        state.tasks.retain(|_, handle| !handle.is_finished());
        state.tasks.len()
    }

    pub async fn task_count(&self) -> usize {
        self.prune_finished().await
    }

    pub async fn shutdown_until(&self, deadline: Instant) -> BackgroundShutdownOutcome {
        loop {
            let notified = self.inner.shutdown_complete.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let mut state = self.inner.state.lock().await;
            state.accepting = false;
            if let Some(outcome) = state.shutdown_outcome {
                return outcome;
            }
            if !state.shutdown_started {
                state.shutdown_started = true;
                let handles = state.tasks.drain().map(|(_, handle)| handle).collect();
                let registry = self.clone();
                tokio::spawn(async move {
                    let mut outcome = wait_or_abort_all(handles, deadline).await;
                    let mut state = registry.inner.state.lock().await;
                    if state.cleanup_required {
                        outcome = BackgroundShutdownOutcome::CleanupRequired;
                    }
                    state.shutdown_outcome = Some(outcome);
                    drop(state);
                    registry.inner.shutdown_complete.notify_waiters();
                });
            }
            drop(state);
            notified.as_mut().await;
        }
    }
}

async fn wait_or_abort_all(
    mut handles: Vec<JoinHandle<()>>,
    deadline: Instant,
) -> BackgroundShutdownOutcome {
    let mut clean = true;
    let mut index = 0;
    while index < handles.len() {
        match tokio::time::timeout_at(deadline, &mut handles[index]).await {
            Ok(Ok(())) => index += 1,
            Ok(Err(_)) => {
                clean = false;
                index += 1;
            }
            Err(_) => {
                clean = false;
                for handle in &handles[index..] {
                    handle.abort();
                }
                for handle in &mut handles[index..] {
                    let _ = handle.await;
                }
                break;
            }
        }
    }
    if clean {
        BackgroundShutdownOutcome::Complete
    } else {
        BackgroundShutdownOutcome::CleanupRequired
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use tokio::sync::{Barrier, Notify};

    use super::*;

    #[tokio::test]
    async fn completed_tasks_prune_and_closed_admission_rejects_without_polling() {
        let registry = BackgroundTaskRegistry::new();
        let finished = Arc::new(Notify::new());
        let signal = Arc::clone(&finished);
        registry
            .spawn(async move { signal.notify_one() })
            .await
            .unwrap();
        finished.notified().await;
        while registry.task_count().await != 0 {
            tokio::task::yield_now().await;
        }
        registry.close_admission().await;
        let polled = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&polled);
        assert_eq!(
            registry
                .spawn(async move { observed.store(true, Ordering::Release) })
                .await,
            Err(BackgroundTaskClosed)
        );
        assert!(!polled.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn deadline_aborts_and_joins_every_pending_task() {
        let registry = BackgroundTaskRegistry::new();
        let entered = Arc::new(Barrier::new(3));
        for _ in 0..2 {
            let entered = Arc::clone(&entered);
            registry
                .spawn(async move {
                    entered.wait().await;
                    std::future::pending::<()>().await;
                })
                .await
                .unwrap();
        }
        entered.wait().await;
        let outcome = registry.shutdown_until(Instant::now()).await;
        assert_eq!(outcome, BackgroundShutdownOutcome::CleanupRequired);
        assert_eq!(registry.task_count().await, 0);
    }

    #[tokio::test]
    async fn completed_task_cleanup_failure_is_sticky_until_shutdown_result() {
        let registry = BackgroundTaskRegistry::new();
        registry.mark_cleanup_required().await;
        assert_eq!(
            registry
                .shutdown_until(Instant::now() + std::time::Duration::from_secs(1))
                .await,
            BackgroundShutdownOutcome::CleanupRequired
        );
    }

    #[tokio::test]
    async fn concurrent_shutdown_callers_observe_one_shared_outcome() {
        let registry = BackgroundTaskRegistry::new();
        let release = Arc::new(Notify::new());
        let released = Arc::clone(&release);
        registry
            .spawn(async move { released.notified().await })
            .await
            .unwrap();
        let first = {
            let registry = registry.clone();
            tokio::spawn(async move {
                registry
                    .shutdown_until(Instant::now() + std::time::Duration::from_secs(5))
                    .await
            })
        };
        while registry.inner.state.lock().await.accepting {
            tokio::task::yield_now().await;
        }
        let second = {
            let registry = registry.clone();
            tokio::spawn(async move {
                registry
                    .shutdown_until(Instant::now() + std::time::Duration::from_secs(5))
                    .await
            })
        };
        release.notify_waiters();
        assert_eq!(first.await.unwrap(), BackgroundShutdownOutcome::Complete);
        assert_eq!(second.await.unwrap(), BackgroundShutdownOutcome::Complete);
        assert_eq!(registry.task_count().await, 0);
    }

    #[tokio::test]
    async fn cancelling_first_shutdown_waiter_does_not_detach_tasks_or_block_retry() {
        let registry = BackgroundTaskRegistry::new();
        let release = Arc::new(Notify::new());
        let released = Arc::clone(&release);
        registry
            .spawn(async move { released.notified().await })
            .await
            .unwrap();
        let first = {
            let registry = registry.clone();
            tokio::spawn(async move {
                registry
                    .shutdown_until(Instant::now() + std::time::Duration::from_secs(5))
                    .await
            })
        };
        while registry.inner.state.lock().await.accepting {
            tokio::task::yield_now().await;
        }
        first.abort();
        let _ = first.await;
        release.notify_waiters();
        assert_eq!(
            registry
                .shutdown_until(Instant::now() + std::time::Duration::from_secs(5))
                .await,
            BackgroundShutdownOutcome::Complete
        );
        assert_eq!(registry.task_count().await, 0);
    }
}
