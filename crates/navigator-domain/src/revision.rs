use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct FencingEpoch(u64);

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("monotonic values must be greater than zero")]
pub struct ZeroMonotonicValue;

impl Revision {
    pub const fn new(value: u64) -> Result<Self, ZeroMonotonicValue> {
        if value == 0 {
            Err(ZeroMonotonicValue)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn initial() -> Self {
        Self(1)
    }

    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for Revision {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl FencingEpoch {
    pub const fn new(value: u64) -> Result<Self, ZeroMonotonicValue> {
        if value == 0 {
            Err(ZeroMonotonicValue)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn is_current(self, current: Self) -> bool {
        self.0 == current.0
    }
}

impl<'de> Deserialize<'de> for FencingEpoch {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}
