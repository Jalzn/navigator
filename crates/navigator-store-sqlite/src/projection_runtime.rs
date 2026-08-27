use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use navigator_domain::SessionId;
use navigator_store_api::{ProjectionStore, StoreError};
use sqlx::Row;
use tokio::{sync::mpsc, task::JoinHandle};
use uuid::Uuid;

use crate::SqliteStore;

/// Capacity-one wake channel backed by durable tail polling. Wake messages are hints only: a
/// dropped hint cannot lose work because each poll derives lag from `SQLite`.
pub struct ProjectionProjector {
    wake: mpsc::Sender<SessionId>,
    dropped: Arc<Mutex<BTreeMap<SessionId, u64>>>,
    task: JoinHandle<()>,
}

impl ProjectionProjector {
    #[must_use]
    pub fn start(store: SqliteStore) -> Self {
        let (wake, mut receiver) = mpsc::channel(1);
        let dropped = Arc::new(Mutex::new(BTreeMap::new()));
        let task_dropped = dropped.clone();
        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(250));
            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    hint = receiver.recv() => if hint.is_none() { break },
                }
                let coalesced =
                    std::mem::take(&mut *task_dropped.lock().expect("projection dropped mutex"));
                if let Err(error) = project_durable_tails(&store, coalesced).await {
                    tracing::warn!(error = ?error, "projection durable-tail poll failed");
                }
            }
        });
        Self {
            wake,
            dropped,
            task,
        }
    }

    /// Best-effort latency hint; full queues deliberately coalesce notifications.
    pub fn notify(&self, session_id: SessionId) {
        if self.wake.try_send(session_id).is_err() {
            let mut dropped = self.dropped.lock().expect("projection dropped mutex");
            *dropped.entry(session_id).or_default() += 1;
        }
    }

    pub async fn shutdown(self) {
        drop(self.wake);
        let _ = self.task.await;
    }
}

async fn project_durable_tails(
    store: &SqliteStore,
    dropped: BTreeMap<SessionId, u64>,
) -> Result<(), StoreError> {
    let rows = sqlx::query(
        "SELECT s.session_id FROM sessions s LEFT JOIN projection_heads h ON h.session_id=s.session_id
         WHERE COALESCE(h.source_head_position,0)<(SELECT COALESCE(MAX(e.position),0) FROM events e WHERE e.session_id=s.session_id)
           AND NOT EXISTS (
             SELECT 1 FROM projection_generations bad
             WHERE bad.session_id=s.session_id AND bad.state='unhealthy'
               AND bad.source_head_position=(SELECT COALESCE(MAX(e.position),0) FROM events e WHERE e.session_id=s.session_id)
           )
         ORDER BY s.session_id LIMIT 128",
    )
    .fetch_all(store.pool())
    .await
    .map_err(|_| StoreError::Unavailable)?;
    for row in rows {
        let raw: String = row.try_get("session_id").map_err(|_| StoreError::Corrupt)?;
        let session = SessionId::from_uuid(Uuid::parse_str(&raw).map_err(|_| StoreError::Corrupt)?)
            .map_err(|_| StoreError::Corrupt)?;
        tracing::debug!(session_id = %session, "projecting durable session tail");
        match store.rebuild_projection(session).await {
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(session_id = %session, error = ?error, "projection session marked unhealthy");
                mark_unhealthy(store, session).await?;
            }
        }
    }
    for (session_id, count) in dropped {
        sqlx::query("UPDATE projection_progress SET dropped_updates=dropped_updates+? WHERE session_id=? AND generation=(SELECT generation FROM projection_heads WHERE session_id=?) AND ordinal=1")
            .bind(i64::try_from(count).map_err(|_|StoreError::Corrupt)?).bind(session_id.to_string()).bind(session_id.to_string()).execute(store.pool()).await.map_err(|_|StoreError::Unavailable)?;
    }
    Ok(())
}

async fn mark_unhealthy(store: &SqliteStore, session: SessionId) -> Result<(), StoreError> {
    let now = store.now();
    sqlx::query("INSERT INTO projection_generations(session_id,generation,state,checkpoint_position,source_head_position,observed_time_floor_seconds,observed_time_floor_nanos,created_at_seconds,created_at_nanos) SELECT ?,COALESCE(MAX(generation),0)+1,'unhealthy',0,(SELECT COALESCE(MAX(position),0) FROM events WHERE session_id=?),?,?,?,? FROM projection_generations WHERE session_id=? HAVING NOT EXISTS (SELECT 1 FROM projection_generations WHERE session_id=? AND state='unhealthy' AND source_head_position=(SELECT COALESCE(MAX(position),0) FROM events WHERE session_id=?))")
        .bind(session.to_string()).bind(session.to_string()).bind(now.unix_seconds()).bind(i64::from(now.nanoseconds())).bind(now.unix_seconds()).bind(i64::from(now.nanoseconds())).bind(session.to_string()).bind(session.to_string()).bind(session.to_string()).execute(store.pool()).await.map_err(|_|StoreError::Unavailable)?;
    Ok(())
}
