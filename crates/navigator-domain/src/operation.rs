use crate::{OperationId, ParticipantId, RequestId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Queued,
    Starting,
    Running,
    Waiting,
    Cancelling,
    Succeeded,
    Failed,
    Cancelled,
    Blocked,
    Uncertain,
}

impl OperationState {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::Blocked | Self::Uncertain
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationAction {
    BeginStart,
    ReportRunning,
    Wait,
    Resume,
    RequestCancel,
    ReportSuccess,
    ReportFailure,
    ReportCancelled,
    ReportBlocked,
    ReportUncertain,
    ObserveIdle,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Operation {
    id: OperationId,
    participant_id: ParticipantId,
    request_id: RequestId,
    state: OperationState,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("operation action {action:?} is not allowed from {from:?}")]
pub struct TransitionError {
    pub from: OperationState,
    pub action: OperationAction,
}

impl Operation {
    #[must_use]
    pub const fn queued(
        id: OperationId,
        participant_id: ParticipantId,
        request_id: RequestId,
    ) -> Self {
        Self {
            id,
            participant_id,
            request_id,
            state: OperationState::Queued,
        }
    }

    #[must_use]
    pub const fn id(&self) -> OperationId {
        self.id
    }

    #[must_use]
    pub const fn participant_id(&self) -> ParticipantId {
        self.participant_id
    }

    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    #[must_use]
    pub const fn state(&self) -> OperationState {
        self.state
    }

    pub fn apply(&mut self, action: OperationAction) -> Result<(), TransitionError> {
        use OperationAction::{
            BeginStart, ReportBlocked, ReportCancelled, ReportFailure, ReportRunning,
            ReportSuccess, ReportUncertain, RequestCancel, Resume, Wait,
        };
        use OperationState::{
            Blocked, Cancelled, Cancelling, Failed, Queued, Running, Starting, Succeeded,
            Uncertain, Waiting,
        };

        let next = match (self.state, action) {
            (Queued, BeginStart) => Starting,
            (Starting, ReportRunning) | (Waiting, Resume) => Running,
            (Running, Wait) => Waiting,
            (Queued | Starting | Running | Waiting, RequestCancel) => Cancelling,
            (Queued | Cancelling, ReportCancelled) => Cancelled,
            (Queued | Starting | Running | Waiting | Cancelling, ReportFailure) => Failed,
            (Running, ReportSuccess) => Succeeded,
            (Running | Waiting, ReportBlocked) => Blocked,
            (Starting | Running | Waiting | Cancelling, ReportUncertain) => Uncertain,
            _ => {
                return Err(TransitionError {
                    from: self.state,
                    action,
                });
            }
        };
        self.state = next;
        Ok(())
    }
}
