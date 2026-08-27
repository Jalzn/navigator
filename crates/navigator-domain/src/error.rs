use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use thiserror::Error;

const MAX_ERROR_MESSAGE_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Validation,
    Authentication,
    Authorization,
    Conflict,
    Capacity,
    Timeout,
    Unavailable,
    Unsupported,
    Incompatible,
    Cancelled,
    UncertainEffect,
    CleanupRequired,
    CorruptedState,
    Internal,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ErrorInfo {
    code: ErrorCode,
    message: String,
    retryable: bool,
}

impl ErrorInfo {
    pub fn new(
        code: ErrorCode,
        message: impl Into<String>,
        retryable: bool,
    ) -> Result<Self, InvalidErrorMessage> {
        let message = message.into();
        if message.is_empty() || message.len() > MAX_ERROR_MESSAGE_BYTES {
            return Err(InvalidErrorMessage);
        }
        Ok(Self {
            code,
            message,
            retryable,
        })
    }

    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub const fn retryable(&self) -> bool {
        self.retryable
    }
}

impl fmt::Debug for ErrorInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ErrorInfo")
            .field("code", &self.code)
            .field("message", &"<redacted>")
            .field("retryable", &self.retryable)
            .finish()
    }
}

impl<'de> Deserialize<'de> for ErrorInfo {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            code: ErrorCode,
            message: String,
            retryable: bool,
        }

        let raw = Raw::deserialize(deserializer)?;
        Self::new(raw.code, raw.message, raw.retryable).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("public error message must contain 1 to 1024 bytes")]
pub struct InvalidErrorMessage;

#[derive(Debug, Error)]
#[error("Navigator operation failed with {code:?}", code = .info.code())]
pub struct NavigatorError {
    pub info: ErrorInfo,
}
