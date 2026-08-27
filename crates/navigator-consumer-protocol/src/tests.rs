use navigator_domain::ErrorCode;
use prost::Message;

use super::{
    ArtifactReadStreamValidator, ArtifactWriteStreamValidator, CAPABILITY_APPROVALS_V1,
    CAPABILITY_ARTIFACTS_V1, CAPABILITY_CONSUMER_TOOLS_V1, CAPABILITY_OPERATIONAL_PROJECTIONS_V1,
    CURRENT_MAJOR, CURRENT_MINOR, MAX_ARTIFACT_CHUNK_BYTES, MAX_CONSUMER_KEY_BYTES,
    MAX_REQUEST_BYTES, MAX_TEMPLATE_AUTHORITY_RULES, MAX_TOOL_SCHEMA_BYTES,
    ToolProviderStreamValidator, ValidateRequest, ValidationError, decode_and_validate, negotiate,
    v1, validate_artifact_snapshot, validate_cancellation_snapshot, validate_failure,
    validate_negotiated, validate_operation_snapshot, validate_recovery_report, validate_snapshot,
    validate_tool_provider_request, validate_tool_specification, validated_root_template,
    validated_session_templates,
};

fn version() -> v1::ProtocolVersion {
    v1::ProtocolVersion {
        major: CURRENT_MAJOR,
        minor: CURRENT_MINOR,
    }
}

fn metadata() -> v1::RequestMetadata {
    v1::RequestMetadata {
        protocol_version: Some(version()),
        capabilities: vec!["events.replay".into()],
        negotiation_id: id(9),
    }
}

fn id(last: u8) -> Vec<u8> {
    let mut value = [0; 16];
    value[15] = last;
    value.to_vec()
}

fn open_request() -> v1::OpenSessionRequest {
    let mut request = v1::OpenSessionRequest {
        metadata: Some(metadata()),
        request_id: id(1),
        session_id: id(2),
        consumer_key: "consumer-a".into(),
        compatibility_identity: Vec::new(),
        root_template: Some(root_template()),
        compatible_templates: Vec::new(),
        configuration_identity: Vec::new(),
        mode: v1::SessionOpenMode::Unspecified.into(),
    };
    request.compatibility_identity = validated_root_template(&request)
        .unwrap()
        .compatibility()
        .as_bytes()
        .to_vec();
    request
}

#[test]
fn open_modes_require_the_negotiated_capability() {
    let mut request = open_request();
    request.mode = v1::SessionOpenMode::Open.into();
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::InvalidCapability)
    );
    request
        .metadata
        .as_mut()
        .unwrap()
        .capabilities
        .push("session.open-modes.v1".into());
    assert_eq!(request.validate_request(), Ok(()));
}

#[test]
fn explicit_template_manifest_is_order_independent_and_binds_configuration() {
    let mut request = open_request();
    request.compatibility_identity.clear();
    request.configuration_identity = vec![9; 32];
    let mut first = root_template();
    first.template_id = id(20);
    first.role = "child-a".into();
    let mut second = root_template();
    second.template_id = id(21);
    second.role = "child-b".into();
    request.compatible_templates = vec![first.clone(), second.clone()];
    let (_, _, first_manifest) = validated_session_templates(&request).unwrap();
    request.compatible_templates = vec![second, first];
    let (_, _, reordered_manifest) = validated_session_templates(&request).unwrap();
    assert_eq!(first_manifest, reordered_manifest);
    request.configuration_identity = vec![8; 32];
    let (_, _, changed_manifest) = validated_session_templates(&request).unwrap();
    assert_ne!(first_manifest, changed_manifest);
}

fn root_template() -> v1::RootTemplateSpecification {
    v1::RootTemplateSpecification {
        template_id: id(10),
        role: "root-worker".into(),
        driver_id: id(11),
        required_capabilities: vec![v1::DriverCapabilityRequirement {
            capability: "durable.acceptance".into(),
            minimum_version: 1,
            parameters: vec![v1::CapabilityParameter {
                key: "mode".into(),
                value: "safe".into(),
            }],
        }],
        trusted_configuration: Some(v1::TrustedTemplateConfiguration {
            base_instructions: "perform the validated task".into(),
            secret_names: vec!["api_token".into()],
        }),
        resources: Some(v1::ParticipantResourceBounds {
            memory_bytes: 1 << 20,
            cpu_millis: 10_000,
            max_concurrent_operations: 1,
        }),
        input_schema: Some(v1::InputSchema {
            fields: vec![v1::InputField {
                name: "task".into(),
                kind: v1::InputKind::String.into(),
                required: true,
                max_string_bytes: Some(1024),
            }],
        }),
        authority_profile: None,
    }
}

fn authority_rule(value: u8) -> v1::ScopedCapabilitySpecification {
    v1::ScopedCapabilitySpecification {
        capability: "tool.records.lookup".into(),
        resource: Some(v1::scoped_capability_specification::Resource::OperationId(
            id(value),
        )),
    }
}

fn validated_template(
    value: &v1::RootTemplateSpecification,
) -> Result<navigator_domain::Template, ValidationError> {
    let mut request = open_request();
    request.root_template = Some(value.clone());
    request.compatibility_identity.clear();
    validated_root_template(&request)
}

#[test]
fn template_authority_is_bounded_exact_and_default_deny() {
    let empty = root_template();
    let empty_template = validated_template(&empty).unwrap();
    assert_eq!(empty_template.authority().active().count(), 0);

    let mut exact = empty.clone();
    let rule = authority_rule(31);
    exact.authority_profile = Some(v1::AuthorityProfileSpecification {
        active: vec![rule.clone()],
        delegable: vec![rule.clone()],
    });
    let exact_template = validated_template(&exact).unwrap();
    assert_eq!(exact_template.authority().active().count(), 1);
    assert_ne!(
        empty_template.compatibility(),
        exact_template.compatibility()
    );

    let mut cross_id = exact.clone();
    cross_id.authority_profile.as_mut().unwrap().active[0] = authority_rule(32);
    cross_id.authority_profile.as_mut().unwrap().delegable[0] = authority_rule(32);
    assert_ne!(
        exact_template.compatibility(),
        validated_template(&cross_id).unwrap().compatibility()
    );

    for profile in [
        v1::AuthorityProfileSpecification {
            active: vec![rule.clone(), rule.clone()],
            delegable: vec![],
        },
        v1::AuthorityProfileSpecification {
            active: vec![],
            delegable: vec![rule.clone()],
        },
        v1::AuthorityProfileSpecification {
            active: vec![authority_rule(0)],
            delegable: vec![],
        },
        v1::AuthorityProfileSpecification {
            active: vec![rule; MAX_TEMPLATE_AUTHORITY_RULES + 1],
            delegable: vec![],
        },
    ] {
        let mut invalid = empty.clone();
        invalid.authority_profile = Some(profile);
        assert!(validated_template(&invalid).is_err());
    }
}

#[test]
fn request_roundtrips_and_ignores_unknown_optional_field() {
    let expected = open_request();
    let mut bytes = expected.encode_to_vec();
    bytes.extend_from_slice(&[0x32, 0x10]);
    bytes.extend_from_slice(&[3; 16]);
    bytes.extend_from_slice(&[0x98, 0x06, 0x01]);
    let decoded = v1::OpenSessionRequest::decode(bytes.as_slice()).unwrap();
    assert_eq!(decoded, expected);
    assert_eq!(decoded.validate_request(), Ok(()));
}

#[test]
fn generated_descriptor_contains_versioned_service() {
    assert!(!v1::FILE_DESCRIPTOR_SET.is_empty());
    assert!(
        v1::FILE_DESCRIPTOR_SET
            .windows(b"NavigatorConsumer".len())
            .any(|value| value == b"NavigatorConsumer")
    );
}

#[test]
fn python_sdk_negotiate_golden_matches_prost() {
    let request = v1::NegotiateRequest {
        minimum_version: Some(v1::ProtocolVersion { major: 1, minor: 0 }),
        maximum_version: Some(v1::ProtocolVersion { major: 1, minor: 0 }),
        capabilities: vec!["events.replay".into()],
    };
    assert_eq!(
        request.encode_to_vec(),
        b"\x0a\x02\x08\x01\x12\x02\x08\x01\x1a\x0devents.replay"
    );
}

#[test]
fn frozen_v1_0_consumer_fixture_negotiates_with_the_current_server() {
    let fixture = include_str!("../fixtures/negotiate-v1_0.hex").trim();
    let bytes = fixture
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect::<Vec<_>>();
    let request = v1::NegotiateRequest::decode(bytes.as_slice()).unwrap();
    let negotiated = negotiate(&request, &["events.replay"], id(99)).unwrap();
    assert_eq!(
        negotiated.protocol_version,
        Some(v1::ProtocolVersion { major: 1, minor: 0 })
    );
    assert_eq!(negotiated.capabilities, ["events.replay"]);
}

#[test]
fn frozen_v1_0_consumer_snapshot_fixture_reaches_a_non_negotiate_endpoint() {
    let fixture = include_str!("../fixtures/snapshot-v1_0.hex").trim();
    let bytes = fixture
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect::<Vec<_>>();
    let request = v1::SnapshotRequest::decode(bytes.as_slice()).unwrap();
    assert_eq!(request.encode_to_vec(), bytes);
    assert_eq!(request.session_id, vec![2; 16]);
    let metadata = request.metadata.unwrap();
    assert_eq!(
        metadata.protocol_version,
        Some(v1::ProtocolVersion { major: 1, minor: 0 })
    );
    assert_eq!(metadata.capabilities, ["events.replay.v1"]);
    assert_eq!(metadata.negotiation_id, vec![1; 16]);
}

#[test]
fn nil_and_malformed_ids_are_rejected() {
    let mut request = open_request();
    request.request_id = vec![0; 16];
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::InvalidIdentity)
    );
    request.request_id = vec![1; 15];
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::InvalidIdentity)
    );
}

#[test]
fn exact_string_edge_is_accepted_and_plus_one_rejected() {
    let mut request = open_request();
    request.consumer_key = "a".repeat(MAX_CONSUMER_KEY_BYTES);
    assert_eq!(request.validate_request(), Ok(()));
    request.consumer_key.push('a');
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::InvalidBound)
    );
}

#[test]
fn encoded_limit_precedes_field_validation() {
    let request = v1::OpenSessionRequest {
        metadata: None,
        request_id: Vec::new(),
        session_id: Vec::new(),
        consumer_key: "x".repeat(MAX_REQUEST_BYTES),
        compatibility_identity: Vec::new(),
        root_template: None,
        compatible_templates: Vec::new(),
        configuration_identity: Vec::new(),
        mode: v1::SessionOpenMode::Unspecified.into(),
    };
    assert!(request.encoded_len() > MAX_REQUEST_BYTES);
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::RequestTooLarge)
    );
}

#[test]
fn unsupported_version_and_invalid_range_are_distinct() {
    let mut request = open_request();
    request.metadata.as_mut().unwrap().protocol_version =
        Some(v1::ProtocolVersion { major: 2, minor: 0 });
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::UnsupportedVersion)
    );
    let negotiation = v1::NegotiateRequest {
        minimum_version: Some(v1::ProtocolVersion { major: 1, minor: 1 }),
        maximum_version: Some(v1::ProtocolVersion { major: 1, minor: 0 }),
        capabilities: Vec::new(),
    };
    assert_eq!(
        negotiation.validate_request(),
        Err(ValidationError::InvalidVersionRange)
    );
}

#[test]
fn duplicate_and_malformed_capabilities_are_rejected() {
    let mut request = open_request();
    request.metadata.as_mut().unwrap().capabilities =
        vec!["events.replay".into(), "events.replay".into()];
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::InvalidCapability)
    );
    request.metadata.as_mut().unwrap().capabilities = vec!["Events Replay".into()];
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::InvalidCapability)
    );
}

#[test]
fn root_template_is_required_and_claimed_compatibility_is_only_an_expectation() {
    let mut request = open_request();
    request.root_template = None;
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::MissingField)
    );

    let mut request = open_request();
    request.compatibility_identity[0] ^= 1;
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::CompatibilityMismatch)
    );

    let mut request = open_request();
    request.compatibility_identity.clear();
    assert!(request.validate_request().is_ok());
}

#[test]
fn root_template_rejects_unregistered_identity_and_duplicate_semantics() {
    let mut request = open_request();
    request.compatibility_identity.clear();
    request.root_template.as_mut().unwrap().template_id = vec![0; 16];
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::InvalidIdentity)
    );

    let mut request = open_request();
    request.compatibility_identity.clear();
    let specification = request.root_template.as_mut().unwrap();
    specification
        .required_capabilities
        .push(specification.required_capabilities[0].clone());
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::InvalidTemplate)
    );

    let mut request = open_request();
    request.compatibility_identity.clear();
    let capability = &mut request
        .root_template
        .as_mut()
        .unwrap()
        .required_capabilities[0];
    capability.parameters.push(capability.parameters[0].clone());
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::InvalidTemplate)
    );

    let mut request = open_request();
    request.compatibility_identity.clear();
    let schema = request
        .root_template
        .as_mut()
        .unwrap()
        .input_schema
        .as_mut()
        .unwrap();
    schema.fields.push(schema.fields[0].clone());
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::InvalidTemplate)
    );

    let mut request = open_request();
    request.compatibility_identity.clear();
    let trusted = request
        .root_template
        .as_mut()
        .unwrap()
        .trusted_configuration
        .as_mut()
        .unwrap();
    trusted.secret_names.push(trusted.secret_names[0].clone());
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::InvalidTemplate)
    );
}

#[test]
fn secret_values_have_no_wire_slot_and_value_shaped_names_fail_closed() {
    let mut request = open_request();
    request.compatibility_identity.clear();
    request
        .root_template
        .as_mut()
        .unwrap()
        .trusted_configuration
        .as_mut()
        .unwrap()
        .secret_names = vec!["api_token=secret-sentinel".into()];
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::InvalidTemplate)
    );

    let encoded = open_request().encode_to_vec();
    assert!(
        !encoded
            .windows(b"secret-sentinel".len())
            .any(|window| window == b"secret-sentinel")
    );
}

#[test]
fn root_template_nested_counts_and_bounds_fail_before_use() {
    let mut request = open_request();
    request.compatibility_identity.clear();
    request.root_template.as_mut().unwrap().role = "x".repeat(super::MAX_TEMPLATE_ROLE_BYTES + 1);
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::InvalidBound)
    );

    let mut request = open_request();
    request.compatibility_identity.clear();
    let field = request
        .root_template
        .as_ref()
        .unwrap()
        .input_schema
        .as_ref()
        .unwrap()
        .fields[0]
        .clone();
    request
        .root_template
        .as_mut()
        .unwrap()
        .input_schema
        .as_mut()
        .unwrap()
        .fields = vec![field; super::MAX_TEMPLATE_INPUT_FIELDS + 1];
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::InvalidTemplate)
    );
}

#[test]
fn zero_stream_cursor_means_from_beginning() {
    let request = v1::SubscribeEventsRequest {
        metadata: Some(metadata()),
        session_id: id(2),
        after_position: 0,
    };
    assert_eq!(request.validate_request(), Ok(()));
}

#[test]
fn bounded_event_poll_is_read_only_shaped_and_rejects_zero_or_plus_one() {
    let mut request = v1::ReadEventsRequest {
        metadata: Some(metadata()),
        session_id: id(2),
        after_position: 0,
        page_size: 128,
    };
    assert_eq!(request.validate_request(), Ok(()));
    request.page_size = 0;
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::InvalidBound)
    );
    request.page_size = 129;
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::InvalidBound)
    );
}

#[test]
fn session_snapshot_exposes_a_valid_root_participant_identity() {
    let mut snapshot = v1::SessionSnapshot {
        session_id: id(1),
        consumer_key: "consumer-a".into(),
        compatibility_identity: vec![1; 32],
        status: v1::SessionStatus::Open.into(),
        revision: 1,
        created_at: Some(v1::Timestamp {
            unix_seconds: 1,
            nanoseconds: 0,
        }),
        updated_at: Some(v1::Timestamp {
            unix_seconds: 1,
            nanoseconds: 1,
        }),
        root_participant_id: id(2),
    };
    assert_eq!(validate_snapshot(&snapshot), Ok(()));
    snapshot.root_participant_id = vec![0; 16];
    assert_eq!(
        validate_snapshot(&snapshot),
        Err(ValidationError::InvalidIdentity)
    );
}

#[test]
fn every_request_shape_roundtrips_and_validates() {
    let negotiation = v1::NegotiateRequest {
        minimum_version: Some(version()),
        maximum_version: Some(version()),
        capabilities: vec!["events.replay".into()],
    };
    let snapshot = v1::SnapshotRequest {
        metadata: Some(metadata()),
        session_id: id(4),
    };
    let close = v1::CloseSessionRequest {
        metadata: Some(metadata()),
        request_id: id(5),
        session_id: id(4),
    };
    let subscribe = v1::SubscribeEventsRequest {
        metadata: Some(metadata()),
        session_id: id(4),
        after_position: 91,
    };
    let start_operation = v1::StartOperationRequest {
        metadata: Some(metadata()),
        request_id: id(6),
        session_id: id(4),
        participant_id: id(7),
        input: b"bounded work".to_vec(),
    };
    let operation_snapshot = v1::OperationSnapshotRequest {
        metadata: Some(metadata()),
        session_id: id(4),
        operation_id: id(8),
    };

    assert_eq!(
        decode_and_validate::<v1::NegotiateRequest>(&negotiation.encode_to_vec()).unwrap(),
        negotiation
    );
    assert_eq!(
        decode_and_validate::<v1::SnapshotRequest>(&snapshot.encode_to_vec()).unwrap(),
        snapshot
    );
    assert_eq!(
        decode_and_validate::<v1::CloseSessionRequest>(&close.encode_to_vec()).unwrap(),
        close
    );
    assert_eq!(
        decode_and_validate::<v1::SubscribeEventsRequest>(&subscribe.encode_to_vec()).unwrap(),
        subscribe
    );
    assert_eq!(
        decode_and_validate::<v1::StartOperationRequest>(&start_operation.encode_to_vec()).unwrap(),
        start_operation
    );
    assert_eq!(
        decode_and_validate::<v1::OperationSnapshotRequest>(&operation_snapshot.encode_to_vec())
            .unwrap(),
        operation_snapshot
    );
}

#[test]
fn operation_snapshot_requires_an_explicit_coherent_terminal_outcome() {
    let mut snapshot = v1::OperationSnapshot {
        operation_id: id(1),
        session_id: id(2),
        participant_id: id(3),
        request_id: id(4),
        status: v1::OperationStatus::Succeeded.into(),
        result: Some(b"done".to_vec()),
        terminal_failure: None,
        revision: 1,
        created_at: Some(v1::Timestamp {
            unix_seconds: 1,
            nanoseconds: 0,
        }),
        updated_at: Some(v1::Timestamp {
            unix_seconds: 2,
            nanoseconds: 0,
        }),
    };
    assert_eq!(validate_operation_snapshot(&snapshot), Ok(()));
    snapshot.result = None;
    assert_eq!(
        validate_operation_snapshot(&snapshot),
        Err(ValidationError::MissingField)
    );
    snapshot.status = v1::OperationStatus::Running.into();
    snapshot.result = Some(b"idle is not success".to_vec());
    assert_eq!(
        validate_operation_snapshot(&snapshot),
        Err(ValidationError::InvalidEnum)
    );
    snapshot.status = v1::OperationStatus::Succeeded.into();
    snapshot.result = Some(b"done".to_vec());
    snapshot.updated_at = Some(v1::Timestamp {
        unix_seconds: 0,
        nanoseconds: 999_999_999,
    });
    assert_eq!(
        validate_operation_snapshot(&snapshot),
        Err(ValidationError::InvalidTimestamp)
    );

    snapshot.status = v1::OperationStatus::Blocked.into();
    snapshot.result = None;
    snapshot.updated_at = Some(v1::Timestamp {
        unix_seconds: 2,
        nanoseconds: 0,
    });
    snapshot.terminal_failure = Some(v1::Failure {
        code: v1::FailureCode::Conflict.into(),
        message: "external change required".into(),
        retry: v1::RetryClass::AfterReconciliation.into(),
        related_id: Some(id(1)),
        details: Vec::new(),
    });
    assert_eq!(validate_operation_snapshot(&snapshot), Ok(()));
    snapshot.terminal_failure = None;
    assert_eq!(
        validate_operation_snapshot(&snapshot),
        Err(ValidationError::MissingField)
    );
}

#[test]
fn cancellation_snapshot_keeps_ack_distinct_and_rejects_duplicate_operations() {
    let operation = v1::OperationSnapshot {
        operation_id: id(1),
        session_id: id(2),
        participant_id: id(3),
        request_id: id(4),
        status: v1::OperationStatus::Cancelling.into(),
        result: None,
        terminal_failure: None,
        revision: 2,
        created_at: Some(v1::Timestamp {
            unix_seconds: 1,
            nanoseconds: 0,
        }),
        updated_at: Some(v1::Timestamp {
            unix_seconds: 2,
            nanoseconds: 0,
        }),
    };
    let record = v1::CancellationOperation {
        operation: Some(operation),
        notification_message_id: id(5),
        driver_acknowledged: true,
    };
    let mut snapshot = v1::CancellationSnapshot {
        root_participant_id: id(3),
        operations: vec![record.clone()],
    };
    assert_eq!(validate_cancellation_snapshot(&snapshot), Ok(()));
    snapshot.operations[0].notification_message_id.clear();
    assert_eq!(
        validate_cancellation_snapshot(&snapshot),
        Err(ValidationError::MissingField)
    );
    snapshot.operations = vec![record.clone(), record];
    assert_eq!(
        validate_cancellation_snapshot(&snapshot),
        Err(ValidationError::InvalidIdentity)
    );
}

#[test]
fn bounded_decoder_rejects_raw_oversize_and_malformed_frames() {
    let oversized = vec![0; MAX_REQUEST_BYTES + 1];
    assert_eq!(
        decode_and_validate::<v1::SnapshotRequest>(&oversized),
        Err(ValidationError::RequestTooLarge)
    );
    assert_eq!(
        decode_and_validate::<v1::SnapshotRequest>(&[0x0a, 0xff]),
        Err(ValidationError::MalformedRequest)
    );
}

#[test]
fn negotiation_returns_only_mutually_supported_capabilities() {
    let request = v1::NegotiateRequest {
        minimum_version: Some(version()),
        maximum_version: Some(version()),
        capabilities: vec!["events.replay".into(), "snapshots".into()],
    };
    let negotiated = negotiate(&request, &["events.replay", "tools"], id(10)).unwrap();
    assert_eq!(negotiated.protocol_version, Some(version()));
    assert_eq!(negotiated.capabilities, ["events.replay"]);
    assert_eq!(negotiated.negotiation_id, id(10));
    assert_eq!(validate_negotiated(&negotiated), Ok(()));
    let roundtrip = v1::Negotiated::decode(negotiated.encode_to_vec().as_slice()).unwrap();
    assert_eq!(roundtrip, negotiated);
}

#[test]
fn negotiation_preserves_a_v1_0_peer_after_minor_extension() {
    let request = v1::NegotiateRequest {
        minimum_version: Some(v1::ProtocolVersion { major: 1, minor: 0 }),
        maximum_version: Some(v1::ProtocolVersion { major: 1, minor: 0 }),
        capabilities: vec!["events.replay".into()],
    };
    let negotiated = negotiate(&request, &["events.replay"], id(11)).unwrap();
    assert_eq!(
        negotiated.protocol_version,
        Some(v1::ProtocolVersion { major: 1, minor: 0 })
    );
}

#[test]
fn request_metadata_requires_a_non_nil_negotiation_identity() {
    let mut request = open_request();
    request.metadata.as_mut().unwrap().negotiation_id.clear();
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::InvalidIdentity)
    );

    request.metadata.as_mut().unwrap().negotiation_id = vec![0; 16];
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::InvalidIdentity)
    );
}

#[test]
fn negotiated_result_without_peer_binding_is_rejected() {
    let negotiated = v1::Negotiated {
        protocol_version: Some(version()),
        capabilities: vec!["events.replay".into()],
        negotiation_id: vec![0; 16],
        configuration_identity: vec![7; 32],
    };
    assert_eq!(
        validate_negotiated(&negotiated),
        Err(ValidationError::InvalidIdentity)
    );
}

#[test]
fn public_failure_requires_stable_typed_classification() {
    let valid = v1::Failure {
        code: v1::FailureCode::Authentication.into(),
        message: "authentication failed".into(),
        retry: v1::RetryClass::Never.into(),
        related_id: None,
        details: Vec::new(),
    };
    assert_eq!(validate_failure(&valid), Ok(()));
    let unspecified = v1::Failure {
        code: v1::FailureCode::Unspecified.into(),
        ..valid
    };
    assert_eq!(
        validate_failure(&unspecified),
        Err(ValidationError::InvalidEnum)
    );
}

#[test]
fn every_canonical_error_code_has_a_valid_wire_representation() {
    const CANONICAL: [ErrorCode; 14] = [
        ErrorCode::Validation,
        ErrorCode::Authentication,
        ErrorCode::Authorization,
        ErrorCode::Conflict,
        ErrorCode::Capacity,
        ErrorCode::Timeout,
        ErrorCode::Unavailable,
        ErrorCode::Unsupported,
        ErrorCode::Incompatible,
        ErrorCode::Cancelled,
        ErrorCode::UncertainEffect,
        ErrorCode::CleanupRequired,
        ErrorCode::CorruptedState,
        ErrorCode::Internal,
    ];

    for canonical in CANONICAL {
        let failure = v1::Failure {
            code: canonical_wire_code(canonical).into(),
            message: "classified failure".into(),
            retry: v1::RetryClass::Never.into(),
            related_id: None,
            details: Vec::new(),
        };
        assert_eq!(validate_failure(&failure), Ok(()), "{canonical:?}");
    }
}

const fn canonical_wire_code(code: ErrorCode) -> v1::FailureCode {
    match code {
        ErrorCode::Validation => v1::FailureCode::InvalidRequest,
        ErrorCode::Authentication => v1::FailureCode::Authentication,
        ErrorCode::Authorization => v1::FailureCode::Authorization,
        ErrorCode::Conflict => v1::FailureCode::Conflict,
        ErrorCode::Capacity => v1::FailureCode::Capacity,
        ErrorCode::Timeout => v1::FailureCode::Timeout,
        ErrorCode::Unavailable => v1::FailureCode::Unavailable,
        ErrorCode::Unsupported => v1::FailureCode::Unsupported,
        ErrorCode::Incompatible => v1::FailureCode::Incompatible,
        ErrorCode::Cancelled => v1::FailureCode::Cancelled,
        ErrorCode::UncertainEffect => v1::FailureCode::UncertainEffect,
        ErrorCode::CleanupRequired => v1::FailureCode::CleanupRequired,
        ErrorCode::CorruptedState => v1::FailureCode::CorruptedState,
        ErrorCode::Internal => v1::FailureCode::Internal,
    }
}

#[test]
fn uncertainty_resolution_requires_explicit_authority_reason_and_proof() {
    let proof = v1::EffectProof {
        kind: v1::EffectProofKind::ExternalCommit.into(),
        digest: vec![7; 32],
        evidence: b"bounded receipt".to_vec(),
    };
    let request = v1::ResolveUncertaintyRequest {
        metadata: Some(metadata()),
        request_id: id(1),
        session_id: id(2),
        operation_id: id(3),
        authority_grant_id: id(4),
        reason: "operator verified the external commit".into(),
        resolution: Some(
            v1::resolve_uncertainty_request::Resolution::ConfirmCompleted(proof.clone()),
        ),
        effect_id: id(8),
    };
    assert_eq!(request.validate_request(), Ok(()));

    let mut missing_authority = request.clone();
    missing_authority.authority_grant_id.clear();
    assert_eq!(
        missing_authority.validate_request(),
        Err(ValidationError::InvalidIdentity)
    );
    let mut blank_reason = request.clone();
    blank_reason.reason = "   ".into();
    assert_eq!(
        blank_reason.validate_request(),
        Err(ValidationError::InvalidBound)
    );
    let mut invalid_proof = request;
    invalid_proof.resolution = Some(
        v1::resolve_uncertainty_request::Resolution::RetryWithEffectProof(v1::EffectProof {
            digest: vec![0; 32],
            ..proof
        }),
    );
    assert_eq!(
        invalid_proof.validate_request(),
        Err(ValidationError::InvalidBound)
    );
}

#[test]
fn resume_is_a_distinct_bounded_command() {
    let request = v1::ResumeSessionRequest {
        metadata: Some(metadata()),
        request_id: id(5),
        session_id: id(6),
    };
    assert_eq!(request.validate_request(), Ok(()));

    let uncertain = v1::RecoveryClassification {
        entity: Some(v1::recovery_classification::Entity::OperationId(id(7))),
        disposition: v1::RecoveryDisposition::EffectUncertain.into(),
        allowed_actions: vec![v1::ResolutionAction::DoNotRetry.into()],
        reason: "effect started without a durable completion proof".into(),
        action_status: v1::RecoveryActionStatus::Pending.into(),
    };
    let report = v1::RecoveryReport {
        session_id: id(6),
        classifications: vec![uncertain.clone()],
    };
    assert_eq!(validate_recovery_report(&report), Ok(()));
    let mut unsafe_report = report;
    unsafe_report.classifications[0].disposition = v1::RecoveryDisposition::SafeToContinue.into();
    assert_eq!(
        validate_recovery_report(&unsafe_report),
        Err(ValidationError::InvalidEnum),
        "ordinary resume must not carry an uncertainty override"
    );
}

#[test]
fn resource_snapshot_point_queries_require_two_valid_identities() {
    let participant = v1::ParticipantSnapshotRequest {
        metadata: Some(metadata()),
        session_id: id(1),
        participant_id: id(2),
    };
    assert_eq!(participant.validate_request(), Ok(()));
    let mut invalid = participant;
    invalid.participant_id.clear();
    assert_eq!(
        invalid.validate_request(),
        Err(ValidationError::InvalidIdentity)
    );

    let message = v1::MessageSnapshotRequest {
        metadata: Some(metadata()),
        session_id: id(1),
        message_id: id(3),
    };
    assert_eq!(message.validate_request(), Ok(()));
    let mut invalid = message;
    invalid.session_id = vec![0; 16];
    assert_eq!(
        invalid.validate_request(),
        Err(ValidationError::InvalidIdentity)
    );
}

fn capability_metadata(capability: &str) -> v1::RequestMetadata {
    let mut value = metadata();
    value.capabilities = vec![capability.into()];
    value
}

fn timestamp(seconds: i64) -> v1::Timestamp {
    v1::Timestamp {
        unix_seconds: seconds,
        nanoseconds: 0,
    }
}

fn tool_specification() -> v1::ToolSpecification {
    v1::ToolSpecification {
        name: "document.extract".into(),
        version: "1.0.0".into(),
        input_schema: br#"{"type":"object"}"#.to_vec(),
        output_schema: br#"{"type":"object"}"#.to_vec(),
        required_authority: "tool.document.extract".into(),
        timeout_millis: 30_000,
        cancellation_behavior: v1::ToolCancellationBehavior::Cooperative.into(),
        effect_class: v1::ToolEffectClass::Idempotent.into(),
        idempotency_contract: v1::ToolIdempotencyContract::InvocationIdentity.into(),
        requires_approval: false,
    }
}

#[test]
fn tool_registration_roundtrips_and_requires_capability() {
    let request = v1::RegisterToolRequest {
        metadata: Some(capability_metadata(CAPABILITY_CONSUMER_TOOLS_V1)),
        request_id: id(31),
        session_id: id(32),
        tool: Some(tool_specification()),
    };
    assert_eq!(request.validate_request(), Ok(()));
    let decoded = v1::RegisterToolRequest::decode(request.encode_to_vec().as_slice()).unwrap();
    assert_eq!(decoded, request);

    let mut missing_capability = request;
    missing_capability
        .metadata
        .as_mut()
        .unwrap()
        .capabilities
        .clear();
    assert_eq!(
        missing_capability.validate_request(),
        Err(ValidationError::InvalidCapability)
    );
}

#[test]
fn projection_reads_are_bounded_and_capability_scoped() {
    let mut request = v1::ReadProjectionRequest {
        metadata: Some(capability_metadata(CAPABILITY_OPERATIONAL_PROJECTIONS_V1)),
        session_id: id(120),
        view: v1::ProjectionView::SessionTree.into(),
        page_size: 128,
        page_token: "resume".into(),
        consumer_key: "consumer".into(),
    };
    assert_eq!(request.validate_request(), Ok(()));
    request.page_size = 129;
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::InvalidBound)
    );
    request.page_size = 1;
    request.view = v1::ProjectionView::Unspecified.into();
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::InvalidBound)
    );
    request.view = v1::ProjectionView::Recovery.into();
    request.metadata.as_mut().unwrap().capabilities = vec!["session.lifecycle.v1".into()];
    assert_eq!(
        request.validate_request(),
        Err(ValidationError::InvalidCapability)
    );
}

#[test]
fn tool_effect_and_idempotency_pairs_fail_closed_under_mutation() {
    let valid = tool_specification();
    assert_eq!(validate_tool_specification(&valid), Ok(()));
    for unknown in [0, 99] {
        let mut mutated = valid.clone();
        mutated.effect_class = unknown;
        assert_eq!(
            validate_tool_specification(&mutated),
            Err(ValidationError::InvalidEnum)
        );
    }
    let mut unsafe_pair = valid.clone();
    unsafe_pair.effect_class = v1::ToolEffectClass::NonIdempotent.into();
    assert_eq!(
        validate_tool_specification(&unsafe_pair),
        Err(ValidationError::InvalidEnum)
    );
    unsafe_pair.idempotency_contract = v1::ToolIdempotencyContract::NeverReplay.into();
    assert_eq!(validate_tool_specification(&unsafe_pair), Ok(()));
}

#[test]
fn tool_schema_and_identifier_bounds_are_exact() {
    let mut valid = tool_specification();
    let prefix = br#"{"properties":{""#;
    let suffix = br#"":{"type":"string"}},"type":"object"}"#;
    valid.input_schema = [
        prefix.as_slice(),
        vec![b'x'; MAX_TOOL_SCHEMA_BYTES - prefix.len() - suffix.len()].as_slice(),
        suffix.as_slice(),
    ]
    .concat();
    assert_eq!(validate_tool_specification(&valid), Ok(()));
    valid
        .input_schema
        .insert(valid.input_schema.len() - suffix.len(), b'x');
    assert_eq!(
        validate_tool_specification(&valid),
        Err(ValidationError::InvalidBound)
    );
    valid.input_schema = vec![0xff];
    assert_eq!(
        validate_tool_specification(&valid),
        Err(ValidationError::InvalidBound)
    );
    valid.input_schema = b"{}".to_vec();
    valid.name = "Uppercase".into();
    assert_eq!(validate_tool_specification(&valid), Ok(()));
    valid.input_schema = br#" {"x":1}"#.to_vec();
    assert_eq!(
        validate_tool_specification(&valid),
        Err(ValidationError::InvalidBound)
    );
    valid.input_schema = b"[]".to_vec();
    assert_eq!(
        validate_tool_specification(&valid),
        Err(ValidationError::InvalidEnum)
    );
    valid.input_schema = b"{}".to_vec();
    valid.timeout_millis = super::MAX_TOOL_TIMEOUT_MILLIS + 1;
    assert_eq!(
        validate_tool_specification(&valid),
        Err(ValidationError::InvalidBound)
    );
    valid.timeout_millis = 1;
    valid.required_authority = "Tool:Unsafe".into();
    assert_eq!(
        validate_tool_specification(&valid),
        Err(ValidationError::InvalidCapability)
    );
}

fn provider_connect(after: u64) -> v1::ToolProviderRequest {
    v1::ToolProviderRequest {
        frame: Some(v1::tool_provider_request::Frame::Connect(
            v1::ConnectToolProvider {
                metadata: Some(capability_metadata(CAPABILITY_CONSUMER_TOOLS_V1)),
                session_id: id(40),
                provider_id: id(41),
                connection_id: id(42),
                after_server_sequence: after,
                registration_ids: vec![id(43)],
            },
        )),
    }
}

fn provider_started(sequence: u64) -> v1::ToolProviderRequest {
    v1::ToolProviderRequest {
        frame: Some(v1::tool_provider_request::Frame::Started(
            v1::ToolHandlerStarted {
                session_id: id(40),
                provider_id: id(41),
                connection_id: id(42),
                invocation_id: id(44),
                dispatch_id: id(45),
                server_sequence: sequence,
                started_at: Some(timestamp(10)),
            },
        )),
    }
}

#[test]
fn provider_stream_requires_connect_and_reconnect_watermark() {
    let mut stream = ToolProviderStreamValidator::default();
    assert_eq!(
        stream.accept(&provider_started(8)),
        Err(ValidationError::MissingField)
    );
    assert_eq!(stream.accept(&provider_connect(7)), Ok(()));
    assert_eq!(
        stream.accept(&provider_started(7)),
        Err(ValidationError::InvalidIdentity)
    );
    let result = v1::ToolProviderRequest {
        frame: Some(v1::tool_provider_request::Frame::Result(
            v1::ToolHandlerResult {
                session_id: id(40),
                provider_id: id(41),
                connection_id: id(42),
                invocation_id: id(44),
                dispatch_id: id(45),
                server_sequence: 8,
                output: b"{}".to_vec(),
                artifacts: Vec::new(),
            },
        )),
    };
    assert_eq!(stream.accept(&result), Err(ValidationError::MissingField));
    assert_eq!(stream.accept(&provider_started(8)), Ok(()));
    // Started and terminal frames correlate the same server delivery sequence.
    assert_eq!(stream.accept(&result), Ok(()));
    assert_eq!(validate_tool_provider_request(&result), Ok(()));
}

#[test]
fn provider_started_correlation_is_exact_and_cross_dispatch_fails_closed() {
    let mut stream = ToolProviderStreamValidator::default();
    stream.accept(&provider_connect(0)).unwrap();
    stream.accept(&provider_started(8)).unwrap();

    assert_eq!(
        stream.accept(&provider_started(9)),
        Err(ValidationError::InvalidIdentity)
    );
    let mut cross_dispatch = provider_started(10);
    if let Some(v1::tool_provider_request::Frame::Started(value)) = &mut cross_dispatch.frame {
        value.dispatch_id = id(46);
    }
    assert_eq!(
        stream.accept(&cross_dispatch),
        Err(ValidationError::InvalidIdentity)
    );
    let mut reused_sequence = provider_started(8);
    if let Some(v1::tool_provider_request::Frame::Started(value)) = &mut reused_sequence.frame {
        value.invocation_id = id(47);
        value.dispatch_id = id(48);
    }
    assert_eq!(
        stream.accept(&reused_sequence),
        Err(ValidationError::InvalidIdentity)
    );
}

#[test]
fn provider_connected_binds_accepted_cursor_and_durable_high_water() {
    let mut connected = v1::ToolProviderResponse {
        frame: Some(v1::tool_provider_response::Frame::Connected(
            v1::ToolProviderConnected {
                session_id: id(40),
                provider_id: id(41),
                connection_id: id(42),
                next_server_sequence: 10,
                accepted_after_server_sequence: 7,
                high_water_server_sequence: 9,
            },
        )),
    };
    assert_eq!(super::validate_tool_provider_response(&connected), Ok(()));
    let Some(v1::tool_provider_response::Frame::Connected(value)) = &mut connected.frame else {
        unreachable!()
    };
    value.accepted_after_server_sequence = 10;
    assert_eq!(
        super::validate_tool_provider_response(&connected),
        Err(ValidationError::ZeroValue)
    );
}

fn artifact_begin(size: u64) -> v1::WriteArtifactRequest {
    v1::WriteArtifactRequest {
        frame: Some(v1::write_artifact_request::Frame::Begin(
            v1::BeginArtifactWrite {
                metadata: Some(capability_metadata(CAPABILITY_ARTIFACTS_V1)),
                request_id: id(50),
                session_id: id(51),
                artifact_id: id(52),
                media_type: "application/octet-stream".into(),
                declared_size: size,
                declared_sha256: vec![7; 32],
                retain_until: Some(timestamp(100)),
                authority_grant_id: Vec::new(),
                creator_participant_id: id(53),
                creator_operation_id: id(54),
            },
        )),
    }
}

fn artifact_chunk(offset: u64, content: Vec<u8>) -> v1::WriteArtifactRequest {
    v1::WriteArtifactRequest {
        frame: Some(v1::write_artifact_request::Frame::Chunk(
            v1::ArtifactChunk {
                artifact_id: id(52),
                offset,
                content,
            },
        )),
    }
}

#[test]
fn artifact_upload_is_bounded_contiguous_and_complete() {
    let mut stream = ArtifactWriteStreamValidator::default();
    assert_eq!(
        stream.accept(&artifact_chunk(0, vec![1])),
        Err(ValidationError::InvalidIdentity)
    );
    assert_eq!(stream.accept(&artifact_begin(3)), Ok(()));
    assert_eq!(stream.accept(&artifact_chunk(0, vec![1, 2])), Ok(()));
    assert_eq!(stream.finish(), Err(ValidationError::InvalidBound));
    assert_eq!(stream.accept(&artifact_chunk(2, vec![3])), Ok(()));
    assert_eq!(stream.finish(), Ok(()));
    assert_eq!(
        stream.accept(&artifact_chunk(3, vec![4])),
        Err(ValidationError::InvalidIdentity)
    );

    let oversized = artifact_chunk(0, vec![0; MAX_ARTIFACT_CHUNK_BYTES + 1]);
    let mut stream = ArtifactWriteStreamValidator::default();
    stream
        .accept(&artifact_begin((MAX_ARTIFACT_CHUNK_BYTES + 1) as u64))
        .unwrap();
    assert_eq!(
        stream.accept(&oversized),
        Err(ValidationError::InvalidBound)
    );

    let mut empty = ArtifactWriteStreamValidator::default();
    assert_eq!(empty.accept(&artifact_begin(0)), Ok(()));
    assert_eq!(empty.finish(), Ok(()));
}

#[test]
fn artifact_snapshot_rejects_traversal_bad_hash_and_unknown_status() {
    let base = v1::ArtifactSnapshot {
        artifact_id: id(60),
        session_id: id(61),
        media_type: "text/plain".into(),
        size: 3,
        sha256: vec![9; 32],
        storage_relative_locator: "sha256/09/content".into(),
        status: v1::ArtifactStatus::Available.into(),
        retain_until: Some(timestamp(100)),
        created_at: Some(timestamp(1)),
        updated_at: Some(timestamp(2)),
        revision: 1,
        creator_participant_id: id(63),
        creator_operation_id: id(64),
    };
    assert_eq!(validate_artifact_snapshot(&base), Ok(()));
    for locator in ["../escape", "/absolute", "safe/../escape", "safe\\escape"] {
        let mut mutated = base.clone();
        mutated.storage_relative_locator = locator.into();
        assert_eq!(
            validate_artifact_snapshot(&mutated),
            Err(ValidationError::InvalidBound)
        );
    }
    let mut mutated = base.clone();
    mutated.sha256.pop();
    assert_eq!(
        validate_artifact_snapshot(&mutated),
        Err(ValidationError::InvalidBound)
    );
    let mut mutated = base;
    mutated.status = 99;
    assert_eq!(
        validate_artifact_snapshot(&mutated),
        Err(ValidationError::InvalidEnum)
    );
}

#[test]
fn new_stream_frames_roundtrip_and_ignore_reserved_unknown_fields() {
    let expected = provider_started(1);
    let mut bytes = expected.encode_to_vec();
    bytes.extend_from_slice(&[0x98, 0x06, 0x01]);
    let decoded = v1::ToolProviderRequest::decode(bytes.as_slice()).unwrap();
    assert_eq!(decoded, expected);
}

#[test]
fn artifact_read_stream_requires_one_header_and_exact_range() {
    let artifact = v1::ArtifactSnapshot {
        artifact_id: id(70),
        session_id: id(71),
        media_type: "text/plain".into(),
        size: 3,
        sha256: vec![3; 32],
        storage_relative_locator: "sha256/03/content".into(),
        status: v1::ArtifactStatus::Available.into(),
        retain_until: Some(timestamp(100)),
        created_at: Some(timestamp(1)),
        updated_at: Some(timestamp(2)),
        revision: 1,
        creator_participant_id: id(73),
        creator_operation_id: id(74),
    };
    let header = v1::ReadArtifactResponse {
        outcome: Some(v1::read_artifact_response::Outcome::Header(
            v1::ArtifactReadHeader {
                artifact: Some(artifact),
                range_offset: 1,
                range_length: 2,
            },
        )),
    };
    let chunk = v1::ReadArtifactResponse {
        outcome: Some(v1::read_artifact_response::Outcome::Chunk(
            v1::ArtifactChunk {
                artifact_id: id(70),
                offset: 1,
                content: vec![2, 3],
            },
        )),
    };
    let mut stream = ArtifactReadStreamValidator::default();
    assert_eq!(stream.accept(&chunk), Err(ValidationError::InvalidIdentity));
    assert_eq!(stream.accept(&header), Ok(()));
    assert_eq!(stream.finish(), Err(ValidationError::InvalidBound));
    assert_eq!(stream.accept(&chunk), Ok(()));
    assert_eq!(stream.finish(), Ok(()));
    assert!(stream.completed_successfully());

    let mut failed = ArtifactReadStreamValidator::default();
    assert_eq!(failed.accept(&header), Ok(()));
    assert_eq!(failed.accept(&chunk), Ok(()));
    let terminal = v1::ReadArtifactResponse {
        outcome: Some(v1::read_artifact_response::Outcome::Failure(v1::Failure {
            code: v1::FailureCode::CorruptedState.into(),
            message: "artifact changed during read".into(),
            retry: v1::RetryClass::Never.into(),
            related_id: None,
            details: Vec::new(),
        })),
    };
    assert_eq!(failed.accept(&terminal), Ok(()));
    assert_eq!(failed.finish(), Ok(()));
    assert!(!failed.completed_successfully());
}

#[test]
fn approval_decisions_are_bounded_and_cannot_carry_broadened_scope() {
    let metadata = v1::RequestMetadata {
        protocol_version: Some(v1::ProtocolVersion { major: 1, minor: 2 }),
        capabilities: vec![CAPABILITY_APPROVALS_V1.into()],
        negotiation_id: id(80),
    };
    let base = v1::ApproveApprovalRequest {
        metadata: Some(metadata.clone()),
        request_id: id(81),
        session_id: id(82),
        approval_id: id(83),
        expected_revision: 1,
        grant_id: id(84),
        grant_expires_at: Some(timestamp(100)),
        max_uses: 1,
    };
    assert_eq!(base.validate_request(), Ok(()));
    for mutant in [
        v1::ApproveApprovalRequest {
            expected_revision: 0,
            ..base.clone()
        },
        v1::ApproveApprovalRequest {
            max_uses: 0,
            ..base.clone()
        },
        v1::ApproveApprovalRequest {
            max_uses: navigator_domain::MAX_APPROVAL_USES + 1,
            ..base.clone()
        },
        v1::ApproveApprovalRequest {
            grant_id: vec![0; 16],
            ..base.clone()
        },
        v1::ApproveApprovalRequest {
            grant_expires_at: None,
            ..base.clone()
        },
        v1::ApproveApprovalRequest {
            metadata: Some(v1::RequestMetadata {
                capabilities: vec!["events.replay.v1".into()],
                ..metadata
            }),
            ..base
        },
    ] {
        assert!(mutant.validate_request().is_err());
    }

    // `ApproveApprovalRequest` has no subject/action/resource fields at the
    // type level: authority scope can only be copied from durable state.
}
