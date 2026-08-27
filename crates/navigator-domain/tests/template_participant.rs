use navigator_domain::{
    BoundedBytes, BoundedText, Capability, DriverCapabilityRequirement, DriverId,
    DriverRequirement, FencingEpoch, InputField, InputKind, InputSchema, InstanceId,
    LaunchAttemptId, LaunchIdentity, ParticipantDomainError, ParticipantId, ResourceBounds,
    RootParticipant, Secret, SessionId, Template, TemplateDomainError, TemplateId, TemplateSecrets,
    TrustedConfiguration,
};
use proptest::prelude::*;
use uuid::Uuid;

fn identity<T>(
    value: u128,
    constructor: fn(Uuid) -> Result<T, navigator_domain::InvalidIdentity>,
) -> T {
    constructor(Uuid::from_u128(value)).unwrap()
}

fn capability(version: u32, parameters: &[(&str, &str)]) -> DriverCapabilityRequirement {
    DriverCapabilityRequirement::new(
        Capability::new("executor.operation").unwrap(),
        version,
        parameters.iter().map(|(key, value)| {
            (
                BoundedText::new((*key).to_owned()).unwrap(),
                BoundedText::new((*value).to_owned()).unwrap(),
            )
        }),
    )
    .unwrap()
}

fn template(instructions: &str, parameters: &[(&str, &str)]) -> Template {
    Template::register(
        identity(1, TemplateId::from_uuid),
        BoundedText::new("root-worker").unwrap(),
        DriverRequirement::new(
            identity(2, DriverId::from_uuid),
            vec![capability(2, parameters)],
        )
        .unwrap(),
        TrustedConfiguration::new(
            BoundedText::new(instructions).unwrap(),
            [BoundedText::new("api_token").unwrap()],
        )
        .unwrap(),
        ResourceBounds::new(1 << 20, 10_000, 1).unwrap(),
        InputSchema::new(vec![
            InputField::new(
                BoundedText::new("task").unwrap(),
                InputKind::String,
                true,
                Some(32),
            )
            .unwrap(),
            InputField::new(
                BoundedText::new("urgent").unwrap(),
                InputKind::Boolean,
                false,
                None,
            )
            .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn template_identity_and_canonical_content_define_compatibility() {
    let first = template(
        "trusted behavior",
        &[("mode", "safe"), ("transport", "stdio")],
    );
    let reordered = template(
        "trusted behavior",
        &[("transport", "stdio"), ("mode", "safe")],
    );
    assert_eq!(first.compatibility(), reordered.compatibility());
    assert!(first.matches_registration(first.template_id(), first.compatibility()));
    assert!(
        !first.matches_registration(identity(99, TemplateId::from_uuid), first.compatibility())
    );
    assert_ne!(
        first.compatibility(),
        template("different behavior", &[("mode", "safe")]).compatibility()
    );
}

#[test]
fn registered_template_snapshot_revalidates_content_on_reopen() {
    let registered = template("trusted behavior", &[("mode", "safe")]);
    let encoded = serde_json::to_vec(&registered.registration_snapshot()).unwrap();
    let snapshot: navigator_domain::RegisteredTemplateSnapshot =
        serde_json::from_slice(&encoded).unwrap();
    assert_eq!(Template::try_from(snapshot).unwrap(), registered);

    let mut corrupt: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    corrupt["role"] = serde_json::Value::String("changed-after-registration".into());
    assert!(
        serde_json::from_value::<navigator_domain::RegisteredTemplateSnapshot>(corrupt).is_err()
    );
}

#[test]
fn secret_rotation_is_not_a_compatibility_boundary_or_public_oracle() {
    let registered = template("trusted behavior", &[]);
    let key = BoundedText::new("api_token").unwrap();
    let first = TemplateSecrets::new([(
        key.clone(),
        Secret::new(BoundedBytes::new(b"secret-sentinel-one".to_vec()).unwrap()),
    )])
    .unwrap();
    let second = TemplateSecrets::new([(
        key.clone(),
        Secret::new(BoundedBytes::new(b"secret-sentinel-two".to_vec()).unwrap()),
    )])
    .unwrap();
    assert_ne!(
        first.get(&key).unwrap().expose(),
        second.get(&key).unwrap().expose()
    );
    let public = serde_json::to_vec(&registered.public_snapshot()).unwrap();
    assert!(
        !public
            .windows(15)
            .any(|window| window == b"secret-sentinel")
    );
    assert_eq!(
        registered.compatibility(),
        template("trusted behavior", &[]).compatibility()
    );
}

#[test]
fn driver_identity_capabilities_versions_and_parameters_are_all_required() {
    let required = DriverRequirement::new(
        identity(2, DriverId::from_uuid),
        vec![capability(2, &[("mode", "safe")])],
    )
    .unwrap();
    assert!(required.is_satisfied_by(
        identity(2, DriverId::from_uuid),
        &[capability(3, &[("mode", "safe"), ("extra", "allowed")])]
    ));
    assert!(!required.is_satisfied_by(
        identity(3, DriverId::from_uuid),
        &[capability(3, &[("mode", "safe")])]
    ));
    assert!(!required.is_satisfied_by(
        identity(2, DriverId::from_uuid),
        &[capability(1, &[("mode", "safe")])]
    ));
    assert!(!required.is_satisfied_by(
        identity(2, DriverId::from_uuid),
        &[capability(3, &[("mode", "unsafe")])]
    ));
    let duplicate = capability(3, &[("mode", "safe")]);
    assert!(!required.is_satisfied_by(
        identity(2, DriverId::from_uuid),
        &[duplicate.clone(), duplicate]
    ));
}

#[test]
fn restoration_recomputes_all_trusted_behavior() {
    let registered = template("trusted behavior", &[("mode", "safe")]);
    let restored = Template::restore_registered(
        registered.template_id(),
        BoundedText::new("root-worker").unwrap(),
        DriverRequirement::new(
            identity(2, DriverId::from_uuid),
            vec![capability(2, &[("mode", "unsafe")])],
        )
        .unwrap(),
        TrustedConfiguration::new(
            BoundedText::new("trusted behavior").unwrap(),
            [BoundedText::new("api_token").unwrap()],
        )
        .unwrap(),
        ResourceBounds::new(1 << 20, 10_000, 1).unwrap(),
        registered.input_schema().clone(),
        registered.compatibility(),
    );
    assert!(matches!(
        restored,
        Err(TemplateDomainError::CompatibilityMismatch)
    ));
}

#[test]
fn duplicate_parameters_and_unbounded_resources_are_rejected() {
    let duplicate = DriverCapabilityRequirement::new(
        Capability::new("executor.operation").unwrap(),
        1,
        [
            (
                BoundedText::new("mode").unwrap(),
                BoundedText::new("one").unwrap(),
            ),
            (
                BoundedText::new("mode").unwrap(),
                BoundedText::new("two").unwrap(),
            ),
        ],
    );
    assert_eq!(
        duplicate,
        Err(TemplateDomainError::DuplicateCapabilityParameter)
    );
    assert_eq!(
        ResourceBounds::new(1, 1, 2),
        Err(TemplateDomainError::InvalidResourceBounds)
    );
}

#[test]
fn numeric_and_utf8_bounds_are_exact() {
    assert!(ResourceBounds::new(1, 1, 1).is_ok());
    assert!(ResourceBounds::new(1 << 40, 86_400_000, 1).is_ok());
    for invalid in [
        ResourceBounds::new(0, 1, 1),
        ResourceBounds::new(1, 0, 1),
        ResourceBounds::new((1 << 40) + 1, 1, 1),
        ResourceBounds::new(1, 86_400_001, 1),
        ResourceBounds::new(1, 1, 0),
    ] {
        assert_eq!(invalid, Err(TemplateDomainError::InvalidResourceBounds));
    }
    let schema = InputSchema::new(vec![
        InputField::new(
            BoundedText::new("task").unwrap(),
            InputKind::String,
            true,
            Some(4),
        )
        .unwrap(),
    ])
    .unwrap();
    assert!(schema.validate(br#"{"task":"abcd"}"#).is_ok());
    assert!(schema.validate(r#"{"task":"éé"}"#.as_bytes()).is_ok());
    assert_eq!(
        schema.validate(r#"{"task":"ééa"}"#.as_bytes()),
        Err(TemplateDomainError::InputFieldType)
    );
}

#[test]
fn task_input_is_bounded_typed_closed_and_canonical() {
    let registered = template("trusted", &[]);
    let left = registered
        .validate_input(br#"{"task":"work","urgent":true}"#)
        .unwrap();
    let right = registered
        .validate_input(br#"{"urgent":true,"task":"work"}"#)
        .unwrap();
    assert_eq!(left, right);
    assert_eq!(
        registered.validate_input(br#"{"task":"work","trusted_instruction":"override"}"#),
        Err(TemplateDomainError::UnknownInputField)
    );
    assert_eq!(
        registered.validate_input(br#"{"task":7}"#),
        Err(TemplateDomainError::InputFieldType)
    );
    assert_eq!(
        registered.validate_input(br#"{"urgent":true}"#),
        Err(TemplateDomainError::MissingInputField)
    );
    assert_eq!(
        registered.validate_input(br#"{"task":"first","task":"second"}"#),
        Err(TemplateDomainError::InvalidTaskInput)
    );
}

#[test]
fn root_participant_has_one_session_and_instance_only_through_launch_identity() {
    let registered = template("trusted", &[]);
    let participant_id = identity(10, ParticipantId::from_uuid);
    let session_id = identity(11, SessionId::from_uuid);
    let mut participant = RootParticipant::new(participant_id, session_id, &registered);
    let launch = LaunchIdentity {
        session_id,
        participant_id,
        launch_attempt_id: identity(12, LaunchAttemptId::from_uuid),
        instance_id: identity(13, InstanceId::from_uuid),
        driver_id: identity(2, DriverId::from_uuid),
        ownership_epoch: FencingEpoch::new(7).unwrap(),
    };
    let forged_session = LaunchIdentity {
        session_id: identity(99, SessionId::from_uuid),
        ..launch
    };
    assert_eq!(
        participant.bind_launch(FencingEpoch::new(7).unwrap(), forged_session),
        Err(ParticipantDomainError::LaunchIdentityMismatch)
    );
    assert_eq!(
        participant.bind_launch(
            FencingEpoch::new(7).unwrap(),
            LaunchIdentity {
                driver_id: identity(99, DriverId::from_uuid),
                ..launch
            }
        ),
        Err(ParticipantDomainError::LaunchIdentityMismatch)
    );
    assert_eq!(
        participant.bind_launch(FencingEpoch::new(8).unwrap(), launch),
        Err(ParticipantDomainError::LaunchIdentityMismatch)
    );
    participant
        .bind_launch(FencingEpoch::new(7).unwrap(), launch)
        .unwrap();
    assert_eq!(participant.snapshot().session_id, session_id);
    assert_eq!(participant.snapshot().current_launch, Some(launch));
    assert_eq!(
        participant.bind_launch(
            FencingEpoch::new(7).unwrap(),
            LaunchIdentity {
                instance_id: identity(14, InstanceId::from_uuid),
                ..launch
            }
        ),
        Err(ParticipantDomainError::CurrentInstanceConflict)
    );
}

static_assertions::assert_not_impl_any!(TemplateSecrets: serde::Serialize, serde::de::DeserializeOwned);
static_assertions::assert_not_impl_any!(Template: serde::de::DeserializeOwned);

proptest! {
    #[test]
    fn arbitrary_oversized_or_wrong_shaped_input_never_validates(extra in 1usize..1024) {
        let registered = template("trusted", &[]);
        let oversized = vec![b'x'; navigator_domain::MAX_INPUT_BYTES + extra];
        prop_assert_eq!(registered.validate_input(&oversized), Err(TemplateDomainError::InputTooLarge));
    }

    #[test]
    fn nonzero_resource_mutation_changes_compatibility(memory in 1u64..(1 << 30)) {
        let base = template("trusted", &[]);
        let mutated = Template::register(
            base.template_id(),
            BoundedText::new("root-worker").unwrap(),
            DriverRequirement::new(identity(2, DriverId::from_uuid), vec![capability(2, &[])]).unwrap(),
            TrustedConfiguration::new(BoundedText::new("trusted").unwrap(), [BoundedText::new("api_token").unwrap()]).unwrap(),
            ResourceBounds::new(memory + (1 << 30), 10_000, 1).unwrap(),
            InputSchema::new(vec![
                InputField::new(BoundedText::new("task").unwrap(), InputKind::String, true, Some(32)).unwrap(),
                InputField::new(BoundedText::new("urgent").unwrap(), InputKind::Boolean, false, None).unwrap(),
            ]).unwrap(),
        ).unwrap();
        prop_assert_ne!(base.compatibility(), mutated.compatibility());
    }
}
