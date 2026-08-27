use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Capability;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SemanticDigest([u8; 32]);

impl SemanticDigest {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// Input bytes must already use the canonical encoding of the owning schema.
    #[must_use]
    pub fn v1(action: &Capability, canonical_input: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"navigator.semantic-input.v1\0");
        digest.update(action.as_str().as_bytes());
        digest.update(b"\0");
        digest.update(canonical_input);
        Self(digest.finalize().into())
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
