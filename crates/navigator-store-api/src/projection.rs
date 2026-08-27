use std::future::Future;

use navigator_domain::{BoundedText, ConsumerKey, EventPosition, RedactedEventData, SessionId};

use crate::StoreError;

pub const MAX_PROJECTION_PAGE_SIZE: u16 = 128;
pub const MAX_PROJECTION_TOKEN_BYTES: usize = 2_048;
pub const MAX_PROJECTION_KEY_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionView {
    SessionTree,
    ActiveWork,
    Delivery,
    Approval,
    Recovery,
    Capacity,
    Failure,
}

impl ProjectionView {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionTree => "session_tree",
            Self::ActiveWork => "active_work",
            Self::Delivery => "delivery",
            Self::Approval => "approval",
            Self::Recovery => "recovery",
            Self::Capacity => "capacity",
            Self::Failure => "failure",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionPageSize(u16);

impl ProjectionPageSize {
    pub const fn new(value: u16) -> Result<Self, StoreError> {
        if value == 0 || value > MAX_PROJECTION_PAGE_SIZE {
            Err(StoreError::Invalid)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

pub type ProjectionPageToken = BoundedText<MAX_PROJECTION_TOKEN_BYTES>;
pub type ProjectionItemKey = BoundedText<MAX_PROJECTION_KEY_BYTES>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadProjection {
    pub session_id: SessionId,
    pub consumer: ConsumerKey,
    pub view: ProjectionView,
    pub page_size: ProjectionPageSize,
    pub page_token: Option<ProjectionPageToken>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionItem {
    pub key: ProjectionItemKey,
    pub data: RedactedEventData,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionPage {
    pub session_id: SessionId,
    pub view: ProjectionView,
    pub generation: u64,
    pub checkpoint_position: Option<EventPosition>,
    pub source_head_position: Option<EventPosition>,
    pub items: Vec<ProjectionItem>,
    pub next_page_token: Option<ProjectionPageToken>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionRebuild {
    pub session_id: SessionId,
    pub generation: u64,
    pub checkpoint_position: Option<EventPosition>,
}

pub trait ProjectionStore: Send + Sync {
    fn rebuild_projection(
        &self,
        session_id: SessionId,
    ) -> impl Future<Output = Result<ProjectionRebuild, StoreError>> + Send;

    fn read_projection(
        &self,
        query: ReadProjection,
    ) -> impl Future<Output = Result<ProjectionPage, StoreError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_size_is_strictly_bounded() {
        assert_eq!(ProjectionPageSize::new(0), Err(StoreError::Invalid));
        assert_eq!(ProjectionPageSize::new(129), Err(StoreError::Invalid));
        assert_eq!(ProjectionPageSize::new(128).unwrap().get(), 128);
    }
}
