use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;

use crate::{ArtifactId, GrantId, OperationId, ParticipantId, SessionId, Timestamp};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Capability(String);

impl Capability {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        {
            return Err("capability must be a bounded lowercase identifier");
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Capability {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Authority(BTreeSet<Capability>);

impl Authority {
    #[must_use]
    pub fn new(capabilities: impl IntoIterator<Item = Capability>) -> Self {
        Self(capabilities.into_iter().collect())
    }

    /// Delegation uses intersection: a child can never gain authority.
    #[must_use]
    pub fn intersect(&self, ceiling: &Self) -> Self {
        Self(self.0.intersection(&ceiling.0).cloned().collect())
    }

    #[must_use]
    pub fn contains(&self, capability: &Capability) -> bool {
        self.0.contains(capability)
    }

    pub fn capabilities(&self) -> impl Iterator<Item = &Capability> {
        self.0.iter()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

pub const MAX_AUTHORITY_RULES: usize = 256;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum ResourceScope {
    Session(SessionId),
    Participant(ParticipantId),
    Operation(OperationId),
    Artifact(ArtifactId),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ScopedCapability {
    pub capability: Capability,
    pub resource: ResourceScope,
}

impl ScopedCapability {
    #[must_use]
    pub const fn new(capability: Capability, resource: ResourceScope) -> Self {
        Self {
            capability,
            resource,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct AuthorityProfile {
    active: BTreeSet<ScopedCapability>,
    delegable: BTreeSet<ScopedCapability>,
}

impl AuthorityProfile {
    pub fn new(
        active: impl IntoIterator<Item = ScopedCapability>,
        delegable: impl IntoIterator<Item = ScopedCapability>,
    ) -> Result<Self, AuthorityError> {
        let active_values: Vec<_> = active.into_iter().collect();
        let delegable_values: Vec<_> = delegable.into_iter().collect();
        let active: BTreeSet<_> = active_values.iter().cloned().collect();
        let delegable: BTreeSet<_> = delegable_values.iter().cloned().collect();
        if active.len() != active_values.len() || delegable.len() != delegable_values.len() {
            return Err(AuthorityError::DuplicateRule);
        }
        if active.len() > MAX_AUTHORITY_RULES || delegable.len() > MAX_AUTHORITY_RULES {
            return Err(AuthorityError::TooManyRules);
        }
        Ok(Self { active, delegable })
    }

    pub fn active(&self) -> impl Iterator<Item = &ScopedCapability> {
        self.active.iter()
    }

    pub fn delegable(&self) -> impl Iterator<Item = &ScopedCapability> {
        self.delegable.iter()
    }

    fn permits_active(&self, requested: &ScopedCapability) -> bool {
        self.active.contains(requested)
    }

    fn permits_delegation(&self, requested: &ScopedCapability) -> bool {
        self.delegable.contains(requested)
    }
}

#[derive(Deserialize)]
struct AuthorityProfileWire {
    active: Vec<ScopedCapability>,
    delegable: Vec<ScopedCapability>,
}

impl<'de> Deserialize<'de> for AuthorityProfile {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = AuthorityProfileWire::deserialize(deserializer)?;
        if wire.active.iter().collect::<BTreeSet<_>>().len() != wire.active.len()
            || wire.delegable.iter().collect::<BTreeSet<_>>().len() != wire.delegable.len()
        {
            return Err(serde::de::Error::custom("duplicate authority rule"));
        }
        Self::new(wire.active, wire.delegable).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Grant {
    pub id: GrantId,
    pub session_id: SessionId,
    pub subject: ParticipantId,
    pub authority: ScopedCapability,
    pub expires_at: Timestamp,
    pub revoked: bool,
}

impl Grant {
    #[must_use]
    pub fn is_active(&self, now: Timestamp) -> bool {
        !self.revoked && now < self.expires_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityCeilings<'a> {
    pub session: &'a AuthorityProfile,
    pub parent: &'a AuthorityProfile,
    pub template: &'a AuthorityProfile,
    pub relationship: &'a AuthorityProfile,
    pub subject: &'a AuthorityProfile,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityOrigin {
    Session,
    ParentDelegation,
    Template,
    Relationship,
    Subject,
    Grant(GrantId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityDecision {
    pub authority: ScopedCapability,
    pub origins: BTreeSet<AuthorityOrigin>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuthorityError {
    #[error("authority rule bound exceeded")]
    TooManyRules,
    #[error("authority rule is duplicated")]
    DuplicateRule,
    #[error("authority denied by a trusted ceiling")]
    Denied,
}

impl AuthorityCeilings<'_> {
    pub fn authorize_child_creation(
        &self,
        requested: &ScopedCapability,
    ) -> Result<AuthorityDecision, AuthorityError> {
        if !self.session.permits_delegation(requested)
            || !self.parent.permits_delegation(requested)
            || !self.template.permits_delegation(requested)
            || !self.relationship.permits_delegation(requested)
            || !self.subject.permits_delegation(requested)
        {
            return Err(AuthorityError::Denied);
        }
        Ok(AuthorityDecision {
            authority: requested.clone(),
            origins: BTreeSet::from([
                AuthorityOrigin::Session,
                AuthorityOrigin::ParentDelegation,
                AuthorityOrigin::Template,
                AuthorityOrigin::Relationship,
                AuthorityOrigin::Subject,
            ]),
        })
    }

    pub fn authorize_effect(
        &self,
        subject: ParticipantId,
        session_id: SessionId,
        requested: &ScopedCapability,
        grant: Option<&Grant>,
        now: Timestamp,
    ) -> Result<AuthorityDecision, AuthorityError> {
        if !self.session.permits_active(requested)
            || !self.parent.permits_delegation(requested)
            || !self.template.permits_active(requested)
            || !self.relationship.permits_active(requested)
            || !self.subject.permits_active(requested)
        {
            return Err(AuthorityError::Denied);
        }
        let mut origins = BTreeSet::from([
            AuthorityOrigin::Session,
            AuthorityOrigin::ParentDelegation,
            AuthorityOrigin::Template,
            AuthorityOrigin::Relationship,
            AuthorityOrigin::Subject,
        ]);
        if let Some(grant) = grant {
            if grant.session_id != session_id
                || grant.subject != subject
                || grant.authority != *requested
                || !grant.is_active(now)
            {
                return Err(AuthorityError::Denied);
            }
            origins.insert(AuthorityOrigin::Grant(grant.id));
        }
        Ok(AuthorityDecision {
            authority: requested.clone(),
            origins,
        })
    }
}
