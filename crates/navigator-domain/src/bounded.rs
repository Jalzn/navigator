use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use thiserror::Error;
use time::{Duration, OffsetDateTime};

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BoundError {
    #[error("value is empty")]
    Empty,
    #[error("value exceeds its byte limit")]
    TooLarge,
    #[error("deadline is not in the future")]
    NotFuture,
    #[error("deadline exceeds maximum future validity")]
    TooFarInFuture,
    #[error("deadline timestamp is invalid")]
    InvalidTimestamp,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundedText<const MAX: usize>(String);

impl<const MAX: usize> BoundedText<MAX> {
    pub fn new(value: impl Into<String>) -> Result<Self, BoundError> {
        let value = value.into();
        if value.is_empty() {
            Err(BoundError::Empty)
        } else if value.len() > MAX {
            Err(BoundError::TooLarge)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<const MAX: usize> Serialize for BoundedText<MAX> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for BoundedText<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BoundedBytes<const MAX: usize>(Vec<u8>);

impl<const MAX: usize> BoundedBytes<MAX> {
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, BoundError> {
        let value = value.into();
        if value.len() > MAX {
            Err(BoundError::TooLarge)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl<const MAX: usize> Serialize for BoundedBytes<MAX> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for BoundedBytes<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Vec::<u8>::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Deadline(OffsetDateTime);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeadlineWire {
    unix_seconds: i64,
    nanoseconds: u32,
}

impl Deadline {
    pub fn new(
        value: OffsetDateTime,
        now: OffsetDateTime,
        max_future: Duration,
    ) -> Result<Self, BoundError> {
        if value <= now {
            Err(BoundError::NotFuture)
        } else if value - now > max_future {
            Err(BoundError::TooFarInFuture)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn value(self) -> OffsetDateTime {
        self.0
    }
}

impl DeadlineWire {
    pub fn new(unix_seconds: i64, nanoseconds: u32) -> Result<Self, BoundError> {
        if nanoseconds >= 1_000_000_000 {
            Err(BoundError::InvalidTimestamp)
        } else {
            Ok(Self {
                unix_seconds,
                nanoseconds,
            })
        }
    }

    pub fn value(self) -> Result<OffsetDateTime, BoundError> {
        OffsetDateTime::from_unix_timestamp(self.unix_seconds)
            .and_then(|value| value.replace_nanosecond(self.nanoseconds))
            .map_err(|_| BoundError::InvalidTimestamp)
    }

    pub fn validate(
        self,
        now: OffsetDateTime,
        max_future: Duration,
    ) -> Result<Deadline, BoundError> {
        Deadline::new(self.value()?, now, max_future)
    }
}

impl Serialize for Deadline {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        DeadlineWire {
            unix_seconds: self.0.unix_timestamp(),
            nanoseconds: self.0.nanosecond(),
        }
        .serialize(serializer)
    }
}

pub struct Secret<T>(T);

impl<T> Secret<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret(<redacted>)")
    }
}
