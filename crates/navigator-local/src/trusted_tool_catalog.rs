use crate::{TrustedToolCatalog, TrustedToolCatalogProvider};
use navigator_domain::{
    AuthorityCeilings, OperationId, ParticipantId, ResourceScope, ScopedCapability, SessionId,
};
use navigator_store_api::{
    AuthorityPolicySnapshot, AuthorityStore, OperationStore, ToolRegistrationSnapshot, ToolStore,
};
use serde_json::{Map, Value};
use std::{future::Future, pin::Pin, sync::Arc};

pub struct StoreTrustedToolCatalog<S> {
    store: Arc<S>,
}
impl<S> StoreTrustedToolCatalog<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }
}

impl<S> TrustedToolCatalogProvider for StoreTrustedToolCatalog<S>
where
    S: ToolStore + AuthorityStore + OperationStore + 'static,
{
    fn catalog(
        &self,
        session_id: SessionId,
        participant_id: ParticipantId,
        operation_id: Option<OperationId>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<TrustedToolCatalog, navigator_core::ExecutorError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            if let Some(operation_id) = operation_id {
                let operation = self
                    .store
                    .load_operation(operation_id)
                    .await
                    .map_err(error)?;
                if operation.session_id != session_id
                    || operation.participant_id != participant_id
                    || operation.operation_id != operation_id
                {
                    return Err(fail("trusted Tool Operation scope mismatch"));
                }
            }
            let registrations = self
                .store
                .list_tool_registrations(session_id)
                .await
                .map_err(error)?;
            if registrations.is_empty() {
                return TrustedToolCatalog::new_bound(
                    Value::Array(Vec::new()),
                    &canonicalize(serde_json::json!({
                        "operation_id": operation_id,
                        "participant_id": participant_id,
                        "registrations": [],
                        "session_id": session_id,
                    })),
                );
            }
            let policy = self
                .store
                .load_authority_policy(participant_id)
                .await
                .map_err(error)?;
            build_catalog(
                session_id,
                participant_id,
                operation_id,
                &policy,
                &registrations,
            )
        })
    }
}

fn build_catalog(
    session_id: SessionId,
    participant_id: ParticipantId,
    operation_id: Option<OperationId>,
    policy: &AuthorityPolicySnapshot,
    registrations: &[ToolRegistrationSnapshot],
) -> Result<TrustedToolCatalog, navigator_core::ExecutorError> {
    if policy.session_id != session_id || policy.participant_id != participant_id {
        return Err(fail("trusted Tool authority scope mismatch"));
    }
    let ceilings = AuthorityCeilings {
        session: &policy.session,
        parent: &policy.parent,
        template: &policy.template,
        relationship: &policy.relationship,
        subject: &policy.subject,
    };
    let mut entries = Vec::new();
    for registration in registrations {
        let Some(operation_id) = operation_id else {
            continue;
        };
        let requested = ScopedCapability::new(
            registration.definition.required_authority().clone(),
            ResourceScope::Operation(operation_id),
        );
        if ceilings
            .authorize_effect(
                participant_id,
                session_id,
                &requested,
                None,
                navigator_domain::Timestamp::new(0, 0).expect("epoch"),
            )
            .is_err()
        {
            continue;
        }
        let schema: Value = serde_json::from_slice(registration.definition.input_schema())
            .map_err(|_| fail("trusted Tool schema is corrupt"))?;
        let mut entry = Map::new();
        entry.insert(
            "registration_id".into(),
            Value::String(registration.registration_id.as_uuid().simple().to_string()),
        );
        entry.insert(
            "name".into(),
            Value::String(registration.definition.name().to_owned()),
        );
        entry.insert(
            "version".into(),
            Value::String(registration.definition.version().to_owned()),
        );
        entry.insert("input_schema".into(), schema);
        entries.push(Value::Object(entry));
        if entries.len() > 64 {
            return Err(fail("trusted Tool catalog exceeds bound"));
        }
    }
    entries.sort_by_key(Value::to_string);
    let mut canonical_registrations = registrations
        .iter()
        .map(|registration| {
            serde_json::json!({
                "definition": registration.definition,
                "registration_id": registration.registration_id,
            })
        })
        .collect::<Vec<_>>();
    canonical_registrations.sort_by_key(Value::to_string);
    let binding = canonicalize(serde_json::json!({
        "operation_id": operation_id,
        "participant_id": participant_id,
        "policy": policy,
        "registrations": canonical_registrations,
        "session_id": session_id,
    }));
    TrustedToolCatalog::new_bound(Value::Array(entries), &binding)
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, canonicalize(value)))
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        scalar => scalar,
    }
}
fn error(value: impl std::fmt::Display) -> navigator_core::ExecutorError {
    fail(&value.to_string())
}
fn fail(value: &str) -> navigator_core::ExecutorError {
    navigator_core::ExecutorError {
        message: value.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{StoreTrustedToolCatalog, build_catalog};
    use crate::TrustedToolCatalogProvider as _;
    use navigator_domain::{
        AuthorityCeilings, AuthorityProfile, BoundedText, CanonicalJson, Capability, ConsumerKey,
        DriverId, DriverRequirement, EffectClass, HostId, IdempotencyContract, InputSchema,
        MessageId, OperationId, ParticipantId, ResourceBounds, ResourceScope, Revision,
        ScopedCapability, SessionId, Template, TemplateId, Timestamp, ToolCancellation,
        ToolDefinition, ToolName, ToolRegistrationId, ToolTimeout, ToolVersion,
        TrustedConfiguration,
    };
    use navigator_store_api::{
        AcquireOwnership, AuthorityPolicySnapshot, CreateRootParticipant, LeaseDuration,
        OpenSession, OperationStore, RequestContext, SessionStore, StartOperation,
        ToolRegistrationSnapshot,
    };
    use navigator_store_sqlite::SqliteStore;
    use std::sync::Arc;
    use tempfile::TempDir;
    use uuid::Uuid;

    fn operation(value: u128) -> OperationId {
        OperationId::from_uuid(Uuid::from_u128(value)).unwrap()
    }

    fn registration(session_id: SessionId, value: u128) -> ToolRegistrationSnapshot {
        ToolRegistrationSnapshot {
            registration_id: ToolRegistrationId::from_uuid(Uuid::from_u128(value)).unwrap(),
            session_id,
            consumer_key: ConsumerKey::new("consumer").unwrap(),
            definition: ToolDefinition::new(
                ToolName::new("Records.Lookup").unwrap(),
                ToolVersion::new("V1").unwrap(),
                CanonicalJson::new(r#"{"type":"object"}"#).unwrap(),
                CanonicalJson::new(r#"{"type":"object"}"#).unwrap(),
                Capability::new("tool.records.lookup").unwrap(),
                ToolTimeout::from_millis(1_000).unwrap(),
                ToolCancellation::Cooperative,
                EffectClass::ReadOnly,
                IdempotencyContract::NoExternalEffect,
            )
            .unwrap(),
            revision: Revision::initial(),
            registered_at: Timestamp::new(1, 0).unwrap(),
        }
    }

    fn policy(
        session_id: SessionId,
        participant_id: ParticipantId,
        extra: bool,
    ) -> AuthorityPolicySnapshot {
        let tool = ScopedCapability::new(
            Capability::new("tool.records.lookup").unwrap(),
            ResourceScope::Session(session_id),
        );
        let extra_capability = ScopedCapability::new(
            Capability::new("unrelated.audit").unwrap(),
            ResourceScope::Session(session_id),
        );
        let active = if extra {
            AuthorityProfile::new([tool.clone(), extra_capability], [tool.clone()]).unwrap()
        } else {
            AuthorityProfile::new([tool.clone()], [tool.clone()]).unwrap()
        };
        let parent = AuthorityProfile::new([tool.clone()], [tool]).unwrap();
        AuthorityPolicySnapshot {
            session_id,
            participant_id,
            session: active.clone(),
            parent,
            template: active.clone(),
            relationship: active.clone(),
            subject: active,
        }
    }

    async fn persisted_operation(
        store: &SqliteStore,
        seed: u128,
    ) -> (SessionId, ParticipantId, OperationId) {
        let host = HostId::from_uuid(Uuid::from_u128(seed + 1)).unwrap();
        let session = SessionId::from_uuid(Uuid::from_u128(seed + 2)).unwrap();
        let participant = ParticipantId::from_uuid(Uuid::from_u128(seed + 3)).unwrap();
        let operation = OperationId::from_uuid(Uuid::from_u128(seed + 4)).unwrap();
        let template = Template::register(
            TemplateId::from_uuid(Uuid::from_u128(seed + 5)).unwrap(),
            BoundedText::new("catalog-real-store").unwrap(),
            DriverRequirement::new(
                DriverId::from_uuid(Uuid::from_u128(seed + 6)).unwrap(),
                vec![],
            )
            .unwrap(),
            TrustedConfiguration::new(BoundedText::new("catalog").unwrap(), []).unwrap(),
            ResourceBounds::new(1024, 1_000, 1).unwrap(),
            InputSchema::new(vec![]).unwrap(),
        )
        .unwrap()
        .registration_snapshot();
        store
            .open_session(OpenSession::new(
                RequestContext::new(
                    navigator_domain::RequestId::from_uuid(Uuid::from_u128(seed + 7)).unwrap(),
                    host,
                ),
                session,
                ConsumerKey::new(format!("catalog-real-store-{seed}")).unwrap(),
                template.compatibility,
            ))
            .await
            .unwrap();
        let epoch = store
            .acquire_ownership(AcquireOwnership::new(
                RequestContext::new(
                    navigator_domain::RequestId::from_uuid(Uuid::from_u128(seed + 8)).unwrap(),
                    host,
                ),
                session,
                LeaseDuration::from_millis(60_000).unwrap(),
            ))
            .await
            .unwrap()
            .value()
            .epoch();
        store.register_template(template.clone()).await.unwrap();
        store
            .create_root_participant(CreateRootParticipant {
                context: RequestContext::new(
                    navigator_domain::RequestId::from_uuid(Uuid::from_u128(seed + 9)).unwrap(),
                    host,
                ),
                session_id: session,
                epoch,
                participant_id: participant,
                template_id: template.identity,
                expected_compatibility: template.compatibility,
            })
            .await
            .unwrap();
        store
            .start_operation(StartOperation {
                context: RequestContext::new(
                    navigator_domain::RequestId::from_uuid(Uuid::from_u128(seed + 10)).unwrap(),
                    host,
                ),
                session_id: session,
                epoch,
                operation_id: operation,
                participant_id: participant,
                input_message_id: MessageId::from_uuid(Uuid::from_u128(seed + 11)).unwrap(),
                input: InputSchema::new(vec![]).unwrap().validate(b"{}").unwrap(),
            })
            .await
            .unwrap();
        (session, participant, operation)
    }

    #[tokio::test]
    async fn provider_rejects_missing_and_cross_bound_operations_from_real_store() {
        let temp = TempDir::new().unwrap();
        let store = Arc::new(
            SqliteStore::open(temp.path().join("catalog.db"))
                .await
                .unwrap(),
        );
        let (session_a, participant_a, operation_a) = persisted_operation(&store, 10_000).await;
        let (session_b, participant_b, _) = persisted_operation(&store, 20_000).await;
        let provider = StoreTrustedToolCatalog::new(store);

        assert!(
            provider
                .catalog(session_b, participant_a, Some(operation_a))
                .await
                .is_err()
        );
        assert!(
            provider
                .catalog(session_a, participant_b, Some(operation_a))
                .await
                .is_err()
        );
        let missing = OperationId::from_uuid(Uuid::from_u128(30_000)).unwrap();
        assert!(
            provider
                .catalog(session_a, participant_a, Some(missing))
                .await
                .is_err()
        );
    }

    fn permits(
        session: &AuthorityProfile,
        parent: &AuthorityProfile,
        template: &AuthorityProfile,
        relationship: &AuthorityProfile,
        subject: &AuthorityProfile,
        requested: &ScopedCapability,
    ) -> bool {
        AuthorityCeilings {
            session,
            parent,
            template,
            relationship,
            subject,
        }
        .authorize_effect(
            ParticipantId::from_uuid(Uuid::from_u128(10)).unwrap(),
            SessionId::from_uuid(Uuid::from_u128(11)).unwrap(),
            requested,
            None,
            Timestamp::new(0, 0).unwrap(),
        )
        .is_ok()
    }

    #[test]
    fn catalog_effect_ceiling_uses_parent_delegable_and_all_other_active_ceilings() {
        let requested = ScopedCapability::new(
            Capability::new("tool.records.lookup").unwrap(),
            ResourceScope::Operation(operation(12)),
        );
        let active_only = AuthorityProfile::new([requested.clone()], []).unwrap();
        let delegable_only = AuthorityProfile::new([], [requested.clone()]).unwrap();
        let both = AuthorityProfile::new([requested.clone()], [requested.clone()]).unwrap();
        let empty = AuthorityProfile::new([], []).unwrap();

        assert!(permits(
            &both,
            &delegable_only,
            &both,
            &both,
            &both,
            &requested
        ));
        assert!(!permits(
            &both,
            &active_only,
            &both,
            &both,
            &both,
            &requested
        ));
        assert!(!permits(
            &empty,
            &delegable_only,
            &both,
            &both,
            &both,
            &requested
        ));
        assert!(!permits(
            &both,
            &delegable_only,
            &empty,
            &both,
            &both,
            &requested
        ));
        assert!(!permits(
            &both,
            &delegable_only,
            &both,
            &empty,
            &both,
            &requested
        ));
        assert!(!permits(
            &both,
            &delegable_only,
            &both,
            &both,
            &empty,
            &requested
        ));
    }

    #[test]
    fn catalog_effect_scope_subsumes_operation_but_never_crosses_exact_operation() {
        let capability = Capability::new("tool.records.lookup").unwrap();
        let operation_a =
            ScopedCapability::new(capability.clone(), ResourceScope::Operation(operation(20)));
        let operation_b =
            ScopedCapability::new(capability.clone(), ResourceScope::Operation(operation(21)));
        let exact = AuthorityProfile::new([operation_a.clone()], [operation_a.clone()]).unwrap();
        assert!(permits(
            &exact,
            &exact,
            &exact,
            &exact,
            &exact,
            &operation_a
        ));
        assert!(!permits(
            &exact,
            &exact,
            &exact,
            &exact,
            &exact,
            &operation_b
        ));

        let another_capability = ScopedCapability::new(
            Capability::new("tool.records.any").unwrap(),
            ResourceScope::Operation(operation(20)),
        );
        let non_subsuming =
            AuthorityProfile::new([another_capability.clone()], [another_capability]).unwrap();
        assert!(!permits(
            &non_subsuming,
            &non_subsuming,
            &non_subsuming,
            &non_subsuming,
            &non_subsuming,
            &operation_a
        ));
    }

    #[test]
    fn real_catalog_builder_binds_exact_scope_policy_and_canonical_registrations() {
        let session_id = SessionId::from_uuid(Uuid::from_u128(30)).unwrap();
        let participant_id = ParticipantId::from_uuid(Uuid::from_u128(31)).unwrap();
        let operation_a = operation(32);
        let operation_b = operation(33);
        let first_registration = registration(session_id, 34);
        let second_registration = registration(session_id, 35);
        let base_policy = policy(session_id, participant_id, false);
        let base = build_catalog(
            session_id,
            participant_id,
            Some(operation_a),
            &base_policy,
            std::slice::from_ref(&first_registration),
        )
        .unwrap();
        let exact = build_catalog(
            session_id,
            participant_id,
            Some(operation_a),
            &base_policy,
            std::slice::from_ref(&first_registration),
        )
        .unwrap();
        assert_eq!(base.identity(), exact.identity());

        let operation_changed = build_catalog(
            session_id,
            participant_id,
            Some(operation_b),
            &base_policy,
            std::slice::from_ref(&first_registration),
        )
        .unwrap();
        let policy_changed = build_catalog(
            session_id,
            participant_id,
            Some(operation_a),
            &policy(session_id, participant_id, true),
            std::slice::from_ref(&first_registration),
        )
        .unwrap();
        let registrations_changed = build_catalog(
            session_id,
            participant_id,
            Some(operation_a),
            &base_policy,
            &[first_registration, second_registration],
        )
        .unwrap();
        for changed in [operation_changed, policy_changed, registrations_changed] {
            assert_ne!(base.identity(), changed.identity());
        }
    }
}
