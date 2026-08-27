//! `SQLite` implementation of Navigator persistence contracts.

mod database;
mod projection_runtime;
mod store;

pub use projection_runtime::ProjectionProjector;
pub use store::SqliteStore;

fn crash_at(point: &str) {
    #[cfg(test)]
    if std::env::var("NAVIGATOR_SQLITE_CRASH_AT").as_deref() == Ok(point) {
        let marker = std::env::var_os("NAVIGATOR_SQLITE_CRASH_MARKER")
            .expect("crash worker marker is configured");
        std::fs::write(marker, point).expect("crash worker marker is written");
        std::process::abort();
    }

    #[cfg(not(test))]
    let _ = point;
}

#[cfg(test)]
mod tests;
