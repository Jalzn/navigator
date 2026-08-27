use core::fmt;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Navigator identity cannot be nil")]
pub struct InvalidIdentity;

pub trait IdentitySource {
    fn next_uuid(&mut self) -> Uuid;
}

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            pub fn from_uuid(value: Uuid) -> Result<Self, InvalidIdentity> {
                if value.is_nil() {
                    Err(InvalidIdentity)
                } else {
                    Ok(Self(value))
                }
            }

            pub fn generate(source: &mut impl IdentitySource) -> Result<Self, InvalidIdentity> {
                Self::from_uuid(source.next_uuid())
            }

            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = Uuid::deserialize(deserializer)?;
                Self::from_uuid(value).map_err(serde::de::Error::custom)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

id_type!(SessionId);
id_type!(HostId);
id_type!(ParticipantId);
id_type!(InstanceId);
id_type!(TemplateId);
id_type!(ArtifactId);
id_type!(ToolInvocationId);
id_type!(ToolRegistrationId);
id_type!(ToolProviderId);
id_type!(ToolConnectionId);
id_type!(ToolDispatchId);
id_type!(ToolCancellationId);
id_type!(GrantId);
id_type!(ApprovalRequestId);
id_type!(DriverId);
id_type!(LaunchAttemptId);
id_type!(OperationId);
id_type!(MessageId);
id_type!(DeliveryAttemptId);
id_type!(EventId);
id_type!(RequestId);
id_type!(CorrelationId);
id_type!(EnvelopeId);
