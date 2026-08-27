//! Owned Instance launch and termination supervision.

mod supervisor;
#[cfg(unix)]
mod unix;

pub use supervisor::*;
#[cfg(unix)]
pub use unix::{OsCredentialSource, UnixProcessBackend};
