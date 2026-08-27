use super::*;
use prost::Message;

fn bytes(value: u8) -> Vec<u8> {
    vec![value; ID_BYTES]
}

fn metadata() -> v1::RequestMetadata {
    v1::RequestMetadata {
        protocol_version: PROTOCOL_V1,
        authentication: Some(v1::Authentication {
            key_id: bytes(1),
            nonce: bytes(2),
            expires_unix_ms: 4_000_000_000_000,
            authenticator: vec![3; 32],
            request_digest: vec![4; 32],
        }),
        required_capabilities: vec![],
        request_id: bytes(5),
    }
}

fn fixture() -> v1::Envelope {
    v1::Envelope {
        envelope_id: bytes(6),
        response_authenticator: Vec::new(),
        response_to_request_id: Vec::new(),
        body: Some(v1::envelope::Body::StartRequest(v1::StartRequest {
            metadata: Some(v1::MutationMetadata {
                request: Some(metadata()),
            }),
            participant_id: bytes(7),
            launch_attempt_id: bytes(8),
            instance_id: bytes(10),
            trusted_configuration: b"deterministic".to_vec(),
            session_id: bytes(9),
            ownership_epoch: 7,
        })),
    }
}

fn sign(envelope: &mut v1::Envelope, participant: &[u8], launch: &[u8]) {
    let digest = canonical_request_digest(envelope).unwrap();
    let envelope_id = envelope.envelope_id.clone();
    let metadata = request_metadata_mut(envelope).unwrap();
    metadata.authentication.as_mut().unwrap().request_digest = digest.to_vec();
    let tag = authentication_tag(
        b"secret",
        &envelope_id,
        &metadata.request_id,
        metadata.protocol_version,
        metadata.authentication.as_ref().unwrap(),
        participant,
        launch,
    )
    .unwrap();
    metadata.authentication.as_mut().unwrap().authenticator = tag.to_vec();
}

#[test]
fn golden_fixture_round_trips() {
    let golden = include_bytes!("../fixtures/start-v1.bin");
    let decoded = decode_envelope(golden).unwrap();
    assert_eq!(decoded, fixture());
    assert_eq!(decoded.encode_to_vec(), golden);
}

#[test]
fn rejects_nil_ids_versions_and_boundaries() {
    let mut value = fixture();
    value.envelope_id = vec![0; 16];
    assert!(matches!(
        value.validate(),
        Err(ValidationError::Invalid("envelope_id"))
    ));
    let mut value = fixture();
    if let Some(v1::envelope::Body::StartRequest(start)) = &mut value.body {
        start
            .metadata
            .as_mut()
            .unwrap()
            .request
            .as_mut()
            .unwrap()
            .protocol_version = 2;
    }
    assert_eq!(value.validate(), Err(ValidationError::UnsupportedVersion));
    let oversized = vec![0; MAX_FRAME_BYTES + 1];
    assert_eq!(
        decode_envelope(&oversized),
        Err(ValidationError::FrameTooLarge)
    );

    for invalid in [vec![0; ID_BYTES], vec![1; ID_BYTES - 1]] {
        let mut value = fixture();
        let Some(v1::envelope::Body::StartRequest(start)) = &mut value.body else {
            unreachable!()
        };
        start.instance_id = invalid;
        assert_eq!(
            value.validate(),
            Err(ValidationError::Invalid("instance_id"))
        );
    }
}

#[test]
fn optional_unknown_fields_remain_compatible() {
    let mut bytes = fixture().encode_to_vec();
    bytes.extend_from_slice(&[0xD8, 0x07, 0x01]);
    assert!(decode_envelope(&bytes).is_ok());
}

#[test]
fn payload_limit_is_exact() {
    let mut value = fixture();
    let Some(v1::envelope::Body::StartRequest(start)) = &mut value.body else {
        unreachable!()
    };
    start.trusted_configuration = vec![1; MAX_CONFIGURATION_BYTES];
    assert!(value.validate().is_ok());
    let Some(v1::envelope::Body::StartRequest(start)) = &mut value.body else {
        unreachable!()
    };
    start.trusted_configuration.push(1);
    assert_eq!(
        value.validate(),
        Err(ValidationError::Oversized("trusted_configuration"))
    );
}

#[test]
fn unknown_required_capability_fails_before_effect() {
    let required = [v1::CapabilityRequirement {
        id: "durable.acceptance".into(),
        minimum_version: 2,
        parameters: vec![],
    }];
    let supported = [v1::Capability {
        id: "durable.acceptance".into(),
        version: 1,
        parameters: vec![],
    }];
    let mut effects = 0;
    if require_capabilities(&required, &supported).is_ok() {
        effects += 1;
    }
    assert_eq!(effects, 0);
}

#[test]
fn authentication_binds_scope_version_and_request() {
    let value = fixture();
    let v1::envelope::Body::StartRequest(request) = value.body.as_ref().unwrap() else {
        unreachable!()
    };
    let metadata = request.metadata.as_ref().unwrap().request.as_ref().unwrap();
    let mut signed = metadata.clone();
    let tag = authentication_tag(
        b"secret",
        &value.envelope_id,
        &signed.request_id,
        signed.protocol_version,
        signed.authentication.as_ref().unwrap(),
        &request.participant_id,
        &request.launch_attempt_id,
    )
    .unwrap();
    signed.authentication.as_mut().unwrap().authenticator = tag.to_vec();
    assert!(
        verify_authentication(
            b"secret",
            &value.envelope_id,
            &signed,
            &request.participant_id,
            &request.launch_attempt_id,
            1
        )
        .is_ok()
    );
    assert!(
        verify_authentication(
            b"secret",
            &value.envelope_id,
            &signed,
            &request.participant_id,
            &bytes(12),
            1
        )
        .is_err()
    );
}

#[test]
fn canonical_auth_rejects_body_mutants_and_replay() {
    let mut signed = fixture();
    let participant = bytes(7);
    let launch = bytes(8);
    sign(&mut signed, &participant, &launch);
    let mut guard = ReplayGuard::new(2).unwrap();
    assert!(
        verify_envelope_authentication(b"secret", &signed, &participant, &launch, 1, &mut guard)
            .is_ok()
    );
    assert!(
        verify_envelope_authentication(b"secret", &signed, &participant, &launch, 1, &mut guard)
            .is_err()
    );
    for mutant in 0..4 {
        let mut changed = signed.clone();
        let Some(v1::envelope::Body::StartRequest(start)) = &mut changed.body else {
            unreachable!()
        };
        match mutant {
            0 => start.trusted_configuration.push(1),
            1 => start.session_id = bytes(10),
            2 => start.ownership_epoch += 1,
            _ => start.instance_id = bytes(11),
        }
        assert_eq!(
            canonical_request_digest(&changed)
                .unwrap()
                .as_slice()
                .ct_eq(
                    request_metadata(&changed)
                        .unwrap()
                        .authentication
                        .as_ref()
                        .unwrap()
                        .request_digest
                        .as_slice()
                )
                .unwrap_u8(),
            0
        );
    }
}

#[test]
fn replay_guard_fails_closed_at_capacity_and_expiry_is_exclusive() {
    let mut guard = ReplayGuard::new(2).unwrap();
    guard.consume(&bytes(1), &bytes(2), 100, 1).unwrap();
    guard.consume(&bytes(1), &bytes(3), 100, 1).unwrap();
    assert_eq!(
        guard.consume(&bytes(1), &bytes(4), 100, 1),
        Err(ValidationError::Oversized("replay_guard"))
    );
    assert_eq!(
        guard.consume(&bytes(1), &bytes(2), 100, 1),
        Err(ValidationError::Invalid("authentication.replay"))
    );
    assert!(guard.consume(&bytes(1), &bytes(4), 200, 100).is_ok());

    let mut signed = fixture();
    let participant = bytes(7);
    let launch = bytes(8);
    sign(&mut signed, &participant, &launch);
    let expires = request_metadata(&signed)
        .unwrap()
        .authentication
        .as_ref()
        .unwrap()
        .expires_unix_ms;
    assert!(
        verify_envelope_authentication(
            b"secret",
            &signed,
            &participant,
            &launch,
            expires,
            &mut ReplayGuard::new(2).unwrap()
        )
        .is_err()
    );
}

#[test]
fn canonical_auth_rejects_delivery_identity_and_payload_mutants() {
    let participant = bytes(7);
    let launch = bytes(8);
    let identity = v1::InstanceIdentity {
        driver_id: bytes(1),
        participant_id: participant.clone(),
        launch_attempt_id: launch.clone(),
        instance_id: bytes(2),
        session_id: bytes(9),
        ownership_epoch: 7,
    };
    let mut envelope = v1::Envelope {
        envelope_id: bytes(6),
        response_authenticator: Vec::new(),
        response_to_request_id: Vec::new(),
        body: Some(v1::envelope::Body::DeliverRequest(v1::DeliverRequest {
            metadata: Some(v1::MutationMetadata {
                request: Some(metadata()),
            }),
            instance: Some(identity),
            message_id: bytes(11),
            delivery_attempt_id: bytes(13),
            operation_id: bytes(12),
            payload: b"payload".to_vec(),
            pending_correlations: vec![],
        })),
    };
    sign(&mut envelope, &participant, &launch);
    for mutant in 0..3 {
        let mut changed = envelope.clone();
        let Some(v1::envelope::Body::DeliverRequest(delivery)) = &mut changed.body else {
            unreachable!()
        };
        match mutant {
            0 => delivery.message_id = bytes(14),
            1 => delivery.payload.push(1),
            _ => delivery.delivery_attempt_id = bytes(15),
        }
        let mut guard = ReplayGuard::new(2).unwrap();
        assert!(
            verify_envelope_authentication(
                b"secret",
                &changed,
                &participant,
                &launch,
                1,
                &mut guard
            )
            .is_err()
        );
    }
}

#[test]
fn delivery_attempt_is_mandatory_and_operation_correlation_is_optional() {
    let mut value = fixture();
    let identity = match value.body.as_ref().unwrap() {
        v1::envelope::Body::StartRequest(start) => v1::InstanceIdentity {
            driver_id: bytes(1),
            participant_id: start.participant_id.clone(),
            launch_attempt_id: start.launch_attempt_id.clone(),
            instance_id: start.instance_id.clone(),
            session_id: start.session_id.clone(),
            ownership_epoch: start.ownership_epoch,
        },
        _ => unreachable!(),
    };
    value.body = Some(v1::envelope::Body::DeliverRequest(v1::DeliverRequest {
        metadata: Some(v1::MutationMetadata {
            request: Some(metadata()),
        }),
        instance: Some(identity),
        message_id: bytes(20),
        operation_id: Vec::new(),
        payload: Vec::new(),
        pending_correlations: Vec::new(),
        delivery_attempt_id: bytes(21),
    }));
    assert!(value.validate().is_ok());
    let v1::envelope::Body::DeliverRequest(delivery) = value.body.as_mut().unwrap() else {
        unreachable!()
    };
    delivery.delivery_attempt_id = vec![0; ID_BYTES];
    assert_eq!(
        value.validate(),
        Err(ValidationError::Invalid("delivery_attempt_id"))
    );
}

#[test]
fn delivery_correlations_reject_ambiguous_mappings() {
    let base = v1::Correlation {
        correlation_id: bytes(30),
        parent_message_id: bytes(31),
    };
    for correlations in [
        vec![base.clone(), base.clone()],
        vec![
            base.clone(),
            v1::Correlation {
                correlation_id: bytes(32),
                parent_message_id: base.parent_message_id.clone(),
            },
        ],
        vec![v1::Correlation {
            correlation_id: bytes(33),
            parent_message_id: bytes(20),
        }],
    ] {
        let envelope = v1::Envelope {
            envelope_id: bytes(6),
            response_authenticator: Vec::new(),
            response_to_request_id: Vec::new(),
            body: Some(v1::envelope::Body::DeliverRequest(v1::DeliverRequest {
                metadata: Some(v1::MutationMetadata {
                    request: Some(metadata()),
                }),
                instance: Some(v1::InstanceIdentity {
                    driver_id: bytes(1),
                    participant_id: bytes(2),
                    launch_attempt_id: bytes(3),
                    instance_id: bytes(4),
                    session_id: bytes(5),
                    ownership_epoch: 1,
                }),
                message_id: bytes(20),
                operation_id: Vec::new(),
                payload: Vec::new(),
                pending_correlations: correlations,
                delivery_attempt_id: bytes(21),
            })),
        };
        assert_eq!(
            envelope.validate(),
            Err(ValidationError::Invalid("pending_correlations.ambiguous"))
        );
    }
}

#[test]
fn capability_parameters_and_duplicates_are_semantic() {
    let required = [v1::CapabilityRequirement {
        id: "stream".into(),
        minimum_version: 1,
        parameters: vec![v1::CapabilityParameter {
            key: "max".into(),
            value: "10".into(),
        }],
    }];
    let supported = [v1::Capability {
        id: "stream".into(),
        version: 1,
        parameters: vec![v1::CapabilityParameter {
            key: "max".into(),
            value: "9".into(),
        }],
    }];
    assert!(matches!(
        require_capabilities(&required, &supported),
        Err(ValidationError::UnsupportedCapability(_))
    ));
    assert_eq!(
        require_capabilities(&[], &[supported[0].clone(), supported[0].clone()]),
        Err(ValidationError::Invalid("capability.duplicate"))
    );
}

#[test]
fn response_oneof_separates_failure_from_semantic_outcome() {
    let typed_failure = v1::Failure {
        code: v1::FailureCode::Authentication as i32,
        message: "denied".into(),
        retryable: false,
    };
    let failure = v1::Envelope {
        envelope_id: bytes(1),
        response_authenticator: Vec::new(),
        response_to_request_id: Vec::new(),
        body: Some(v1::envelope::Body::DeliverResponse(v1::DeliverResponse {
            in_reply_to: bytes(2),
            result: Some(v1::deliver_response::Result::Failure(typed_failure)),
        })),
    };
    assert!(failure.validate().is_ok());
    let unknown = v1::Envelope {
        envelope_id: bytes(1),
        response_authenticator: Vec::new(),
        response_to_request_id: Vec::new(),
        body: Some(v1::envelope::Body::DeliverResponse(v1::DeliverResponse {
            in_reply_to: bytes(2),
            result: Some(v1::deliver_response::Result::Success(v1::DeliverResult {
                acceptance: v1::Acceptance::Unknown as i32,
                message_id: bytes(3),
                delivery_attempt_id: bytes(4),
            })),
        })),
    };
    assert!(unknown.validate().is_ok());
    let mut wrong_attempt = unknown.clone();
    let Some(v1::envelope::Body::DeliverResponse(response)) = wrong_attempt.body.as_mut() else {
        panic!("deliver response fixture");
    };
    let Some(v1::deliver_response::Result::Success(result)) = response.result.as_mut() else {
        panic!("deliver result fixture");
    };
    result.delivery_attempt_id.clear();
    assert_eq!(
        wrong_attempt.validate(),
        Err(ValidationError::Invalid("delivery_attempt_id"))
    );
    let missing = v1::Envelope {
        envelope_id: bytes(1),
        response_authenticator: Vec::new(),
        response_to_request_id: Vec::new(),
        body: Some(v1::envelope::Body::DeliverResponse(v1::DeliverResponse {
            in_reply_to: bytes(2),
            result: None,
        })),
    };
    assert_eq!(
        missing.validate(),
        Err(ValidationError::Missing("delivery.result"))
    );
}

#[test]
fn uncertain_stop_remains_a_semantic_result() {
    for disposition in [
        v1::StopDisposition::StopUncertain,
        v1::StopDisposition::StopCleanupRequired,
    ] {
        let envelope = v1::Envelope {
            envelope_id: bytes(1),
            response_authenticator: Vec::new(),
            response_to_request_id: Vec::new(),
            body: Some(v1::envelope::Body::StopResponse(v1::StopResponse {
                in_reply_to: bytes(2),
                result: Some(v1::stop_response::Result::Success(v1::StopResult {
                    disposition: disposition as i32,
                })),
            })),
        };
        assert!(envelope.validate().is_ok());
    }
}

#[test]
fn response_mac_rejects_forgery_body_mutation_cross_request_and_wrong_key() {
    let secret = b"response-secret-response-secret";
    let mut response = v1::Envelope {
        envelope_id: bytes(1),
        response_authenticator: Vec::new(),
        response_to_request_id: bytes(2),
        body: Some(v1::envelope::Body::DeliverResponse(v1::DeliverResponse {
            in_reply_to: bytes(3),
            result: Some(v1::deliver_response::Result::Success(v1::DeliverResult {
                acceptance: v1::Acceptance::Accepted as i32,
                message_id: bytes(4),
                delivery_attempt_id: bytes(5),
            })),
        })),
    };
    assert!(verify_response(secret, &response).is_err());
    sign_response(secret, &mut response).unwrap();
    assert!(verify_response(secret, &response).is_ok());
    assert!(verify_response(b"wrong-secret-wrong-secret-wrong!", &response).is_err());
    let mut mutated = response.clone();
    let Some(v1::envelope::Body::DeliverResponse(value)) = &mut mutated.body else {
        unreachable!()
    };
    value.in_reply_to = bytes(4);
    assert!(verify_response(secret, &mutated).is_err());
    let mut cross_request = response;
    cross_request.response_to_request_id = bytes(5);
    assert!(verify_response(secret, &cross_request).is_err());
}

fn report_event(
    operation: u8,
    message: u8,
    kind: v1::ReportKind,
    sequence: u64,
) -> v1::DriverEvent {
    v1::DriverEvent {
        event_id: bytes(u8::try_from(sequence).unwrap()),
        instance: Some(report_instance()),
        sequence,
        in_reply_to: bytes(30),
        event: Some(v1::driver_event::Event::Report(v1::Report {
            operation_id: bytes(operation),
            message_id: bytes(message),
            delivery_attempt_id: bytes(23),
            result: Some(v1::report::Result::Outcome(v1::ReportOutcome {
                kind: kind as i32,
                payload: Vec::new(),
            })),
        })),
    }
}

#[test]
fn report_requires_a_non_nil_delivery_attempt_identity() {
    let mut event = report_event(20, 21, v1::ReportKind::Progress, 1);
    let Some(v1::driver_event::Event::Report(report)) = event.event.as_mut() else {
        unreachable!();
    };
    report.delivery_attempt_id.clear();
    assert_eq!(
        v1::Envelope {
            envelope_id: event.event_id.clone(),
            response_authenticator: Vec::new(),
            response_to_request_id: Vec::new(),
            body: Some(v1::envelope::Body::Event(event)),
        }
        .validate(),
        Err(ValidationError::Invalid("delivery_attempt_id"))
    );
}

#[test]
fn approval_request_is_a_distinct_bounded_nonterminal_report() {
    let mut event = report_event(20, 21, v1::ReportKind::Progress, 1);
    let Some(v1::driver_event::Event::Report(report)) = event.event.as_mut() else {
        unreachable!()
    };
    report.result = Some(v1::report::Result::ApprovalRequest(
        v1::ApprovalRequestReport {
            capability: "repo.publish".into(),
            resource: br#"{"branch":"main"}"#.to_vec(),
            summary: "publish main".into(),
            expires_at: Some(v1::ApprovalTimestamp {
                unix_seconds: 200,
                nanoseconds: 0,
            }),
        },
    ));
    let envelope = v1::Envelope {
        envelope_id: event.event_id.clone(),
        response_authenticator: Vec::new(),
        response_to_request_id: Vec::new(),
        body: Some(v1::envelope::Body::Event(event.clone())),
    };
    assert_eq!(envelope.validate(), Ok(()));
    let mut guard = OperationReportGuard::new(bytes(20), bytes(21), report_instance()).unwrap();
    assert_eq!(guard.observe(&event), Ok(SettlementAction::Continue));

    let Some(v1::driver_event::Event::Report(report)) = event.event.as_mut() else {
        unreachable!()
    };
    let Some(v1::report::Result::ApprovalRequest(request)) = report.result.as_mut() else {
        unreachable!()
    };
    request.expires_at.as_mut().unwrap().nanoseconds = 1_000_000_000;
    let invalid = v1::Envelope {
        envelope_id: event.event_id.clone(),
        response_authenticator: Vec::new(),
        response_to_request_id: Vec::new(),
        body: Some(v1::envelope::Body::Event(event)),
    };
    assert_eq!(
        invalid.validate(),
        Err(ValidationError::Invalid("approval.expires_at"))
    );
}

fn report_instance() -> v1::InstanceIdentity {
    v1::InstanceIdentity {
        driver_id: bytes(10),
        participant_id: bytes(11),
        launch_attempt_id: bytes(12),
        instance_id: bytes(13),
        session_id: bytes(14),
        ownership_epoch: 1,
    }
}

#[test]
fn report_guard_rejects_ambiguous_correlation_and_never_coalesces_terminal_reports() {
    let mut guard = OperationReportGuard::new(bytes(20), bytes(21), report_instance()).unwrap();
    assert_eq!(
        guard.observe(&report_event(20, 21, v1::ReportKind::Progress, 1)),
        Ok(SettlementAction::Continue)
    );
    assert_eq!(
        guard.observe(&report_event(20, 22, v1::ReportKind::Succeeded, 2)),
        Err(ValidationError::Invalid("report.correlation"))
    );
    let mut forged_instance = report_event(20, 21, v1::ReportKind::Succeeded, 2);
    forged_instance.instance.as_mut().unwrap().instance_id = bytes(99);
    assert_eq!(
        guard.observe(&forged_instance),
        Err(ValidationError::Invalid("report.instance"))
    );
    let terminal = report_event(20, 21, v1::ReportKind::Succeeded, 3);
    assert_eq!(
        guard.observe(&terminal),
        Ok(SettlementAction::Terminal(v1::ReportKind::Succeeded))
    );
    assert_eq!(
        guard.observe(&terminal),
        Ok(SettlementAction::Terminal(v1::ReportKind::Succeeded)),
        "an uncommitted terminal replay must not be coalesced"
    );
    assert_eq!(
        guard.observe(&report_event(20, 21, v1::ReportKind::ReportFailed, 4)),
        Err(ValidationError::Invalid("report.terminal_conflict"))
    );
    guard.terminal_committed(&terminal.event_id).unwrap();
    assert_eq!(
        guard.observe(&terminal),
        Err(ValidationError::Invalid("report.after_terminal"))
    );
}

#[test]
fn idle_settlement_gets_one_reminder_then_deadline_never_success() {
    let mut guard = OperationReportGuard::new(bytes(20), bytes(21), report_instance()).unwrap();
    assert_eq!(guard.settled_without_report(), SettlementAction::Remind);
    assert_eq!(guard.settled_without_report(), SettlementAction::Deadline);
    assert_ne!(
        guard.settled_without_report(),
        SettlementAction::Terminal(v1::ReportKind::Succeeded)
    );
}

#[test]
fn disconnect_is_observed_without_turning_durable_work_into_cancellation() {
    let mut guard = OperationReportGuard::new(bytes(20), bytes(21), report_instance()).unwrap();
    let mut event = report_event(20, 21, v1::ReportKind::Progress, 1);
    event.event = Some(v1::driver_event::Event::Disconnected(v1::Disconnected {
        reason: "transport lost".into(),
        ownership_lost: false,
    }));
    assert_eq!(guard.observe(&event), Ok(SettlementAction::Disconnected));
    assert_eq!(
        guard.observe(&report_event(20, 21, v1::ReportKind::Succeeded, 2)),
        Ok(SettlementAction::Terminal(v1::ReportKind::Succeeded))
    );
}

#[test]
fn hierarchy_command_has_no_caller_or_trusted_policy_slots_and_is_bounded() {
    let command = v1::HierarchyCommand {
        request_id: bytes(31),
        command: Some(v1::hierarchy_command::Command::SpawnChild(
            v1::SpawnChildCommand {
                template_id: bytes(32),
                task_input: vec![b'x'; MAX_PAYLOAD_BYTES],
                grant_id: Vec::new(),
            },
        )),
    };
    let mut envelope = v1::Envelope {
        envelope_id: bytes(33),
        response_authenticator: Vec::new(),
        response_to_request_id: Vec::new(),
        body: Some(v1::envelope::Body::Event(v1::DriverEvent {
            event_id: bytes(34),
            instance: Some(report_instance()),
            sequence: 1,
            event: Some(v1::driver_event::Event::HierarchyCommand(command.clone())),
            in_reply_to: bytes(35),
        })),
    };
    assert_eq!(envelope.validate(), Ok(()));
    let Some(v1::envelope::Body::Event(event)) = envelope.body.as_mut() else {
        unreachable!()
    };
    let Some(v1::driver_event::Event::HierarchyCommand(command)) = event.event.as_mut() else {
        unreachable!()
    };
    let Some(v1::hierarchy_command::Command::SpawnChild(spawn)) = command.command.as_mut() else {
        unreachable!()
    };
    spawn.task_input.push(b'x');
    assert_eq!(
        envelope.validate(),
        Err(ValidationError::Oversized("hierarchy.input"))
    );
}

#[test]
fn hierarchy_result_authentication_is_bound_to_the_exact_instance_scope() {
    let instance = report_instance();
    let participant = instance.participant_id.clone();
    let launch = instance.launch_attempt_id.clone();
    let mut envelope = v1::Envelope {
        envelope_id: bytes(40),
        response_authenticator: Vec::new(),
        response_to_request_id: Vec::new(),
        body: Some(v1::envelope::Body::HierarchyResultRequest(
            v1::HierarchyResultRequest {
                metadata: Some(v1::MutationMetadata {
                    request: Some(metadata()),
                }),
                instance: Some(instance),
                hierarchy_request_id: bytes(41),
                result: Some(v1::hierarchy_result_request::Result::Sent(
                    v1::MessageAcceptedResult {
                        message_id: bytes(42),
                    },
                )),
            },
        )),
    };
    sign(&mut envelope, &participant, &launch);
    assert_eq!(envelope.validate(), Ok(()));
    assert!(
        verify_envelope_authentication(
            b"secret",
            &envelope,
            &participant,
            &launch,
            1,
            &mut ReplayGuard::new(2).unwrap(),
        )
        .is_ok()
    );
    let mut forged_participant = participant;
    forged_participant[0] ^= 1;
    assert!(
        verify_envelope_authentication(
            b"secret",
            &envelope,
            &forged_participant,
            &launch,
            1,
            &mut ReplayGuard::new(2).unwrap(),
        )
        .is_err()
    );
}

fn tool_event() -> v1::Envelope {
    let instance = report_instance();
    v1::Envelope {
        envelope_id: bytes(60),
        response_authenticator: Vec::new(),
        response_to_request_id: Vec::new(),
        body: Some(v1::envelope::Body::Event(v1::DriverEvent {
            event_id: bytes(60),
            instance: Some(instance.clone()),
            sequence: 1,
            event: Some(v1::driver_event::Event::ToolCommand(v1::ToolCommand {
                request_id: bytes(61),
                session_id: instance.session_id,
                participant_id: instance.participant_id,
                operation_id: bytes(62),
                tool_name: "records.lookup".into(),
                tool_version: "v1".into(),
                input: br#"{"id":1}"#.to_vec(),
                authority_grant_id: Vec::new(),
                approval_grant_id: Vec::new(),
            })),
            in_reply_to: bytes(63),
        })),
    }
}

#[test]
fn tool_command_is_bounded_and_bound_to_authenticated_instance_context() {
    let value = tool_event();
    assert_eq!(value.validate(), Ok(()));
    let mut uppercase = value.clone();
    let Some(v1::envelope::Body::Event(event)) = uppercase.body.as_mut() else {
        unreachable!()
    };
    let Some(v1::driver_event::Event::ToolCommand(command)) = event.event.as_mut() else {
        unreachable!()
    };
    command.tool_name = "Records.Lookup".into();
    command.tool_version = "V1".into();
    assert_eq!(uppercase.validate(), Ok(()));
    for invalid in ["bad@name", "éclair", "has space", ".leading", "trailing-"] {
        let mut mutant = uppercase.clone();
        let Some(v1::envelope::Body::Event(event)) = mutant.body.as_mut() else {
            unreachable!()
        };
        let Some(v1::driver_event::Event::ToolCommand(command)) = event.event.as_mut() else {
            unreachable!()
        };
        command.tool_name = invalid.into();
        assert_eq!(
            mutant.validate(),
            Err(ValidationError::Invalid("tool.name"))
        );
    }

    let mut mutant = value.clone();
    let Some(v1::envelope::Body::Event(event)) = mutant.body.as_mut() else {
        unreachable!()
    };
    let Some(v1::driver_event::Event::ToolCommand(command)) = event.event.as_mut() else {
        unreachable!()
    };
    command.participant_id = bytes(99);
    assert_eq!(
        mutant.validate(),
        Err(ValidationError::Invalid("tool.caller_context"))
    );

    let mut mutant = value.clone();
    let Some(v1::envelope::Body::Event(event)) = mutant.body.as_mut() else {
        unreachable!()
    };
    let Some(v1::driver_event::Event::ToolCommand(command)) = event.event.as_mut() else {
        unreachable!()
    };
    command.input = vec![b'x'; MAX_TOOL_INPUT_BYTES + 1];
    assert_eq!(
        mutant.validate(),
        Err(ValidationError::Oversized("tool.input"))
    );

    let mut mutant = value;
    let Some(v1::envelope::Body::Event(event)) = mutant.body.as_mut() else {
        unreachable!()
    };
    let Some(v1::driver_event::Event::ToolCommand(command)) = event.event.as_mut() else {
        unreachable!()
    };
    command.input = br#"{ "id": 1 }"#.to_vec();
    assert_eq!(
        mutant.validate(),
        Err(ValidationError::Invalid("tool.input"))
    );
}

#[test]
fn tool_correlation_accepts_exact_replay_and_rejects_mutants() {
    let envelope = tool_event();
    let Some(v1::envelope::Body::Event(event)) = envelope.body else {
        unreachable!()
    };
    let Some(v1::driver_event::Event::ToolCommand(command)) = event.event else {
        unreachable!()
    };
    let mut guard = ToolCorrelationGuard::default();
    assert_eq!(
        guard.observe_command(&command),
        Ok(ToolCorrelationDisposition::New)
    );
    assert_eq!(
        guard.observe_command(&command),
        Ok(ToolCorrelationDisposition::Duplicate)
    );
    let mut conflict = command.clone();
    conflict.input = br#"{"id":2}"#.to_vec();
    assert_eq!(
        guard.observe_command(&conflict),
        Err(ValidationError::Invalid("tool.request_conflict"))
    );

    let result = v1::ToolResultRequest {
        metadata: Some(v1::MutationMetadata {
            request: Some(metadata()),
        }),
        instance: Some(report_instance()),
        tool_request_id: command.request_id,
        result: Some(v1::tool_result_request::Result::Success(
            v1::ToolCallResult {
                output: br#"{"found":true}"#.to_vec(),
                artifacts: vec![],
            },
        )),
    };
    assert_eq!(
        guard.observe_result(&result),
        Ok(ToolCorrelationDisposition::New)
    );
    assert_eq!(
        guard.observe_result(&result),
        Ok(ToolCorrelationDisposition::Duplicate)
    );
    let mut conflict = result;
    conflict.result = Some(v1::tool_result_request::Result::Failure(v1::Failure {
        code: v1::FailureCode::Internal.into(),
        message: "failed".into(),
        retryable: false,
    }));
    assert_eq!(
        guard.observe_result(&conflict),
        Err(ValidationError::Invalid("tool.terminal_conflict"))
    );
}

#[test]
fn tool_artifact_references_are_complete_and_bounded() {
    let artifact = v1::ToolArtifactReference {
        artifact_id: bytes(71),
        session_id: bytes(72),
        creator_participant_id: bytes(73),
        creator_operation_id: bytes(74),
        media_type: "application/octet-stream".into(),
        size: MAX_ARTIFACT_BYTES,
        sha256: vec![7; ARTIFACT_SHA256_BYTES],
    };
    let valid = v1::ToolCallResult {
        output: br#"{"ok":true}"#.to_vec(),
        artifacts: vec![artifact.clone()],
    };
    assert_eq!(tool_result(&valid), Ok(()));

    let mut mutant = valid.clone();
    mutant.artifacts = vec![artifact.clone(); MAX_TOOL_ARTIFACT_REFS + 1];
    assert_eq!(
        tool_result(&mutant),
        Err(ValidationError::Oversized("tool.artifacts"))
    );
    let mut mutant = valid.clone();
    mutant.artifacts[0].creator_operation_id.clear();
    assert_eq!(
        tool_result(&mutant),
        Err(ValidationError::Invalid(
            "tool.artifact.creator_operation_id"
        ))
    );
    let mut mutant = valid.clone();
    mutant.artifacts[0].size = MAX_ARTIFACT_BYTES + 1;
    assert_eq!(
        tool_result(&mutant),
        Err(ValidationError::Oversized("tool.artifact.size"))
    );
    let mut mutant = valid;
    mutant.artifacts[0].sha256.pop();
    assert_eq!(
        tool_result(&mutant),
        Err(ValidationError::Invalid("tool.artifact.sha256"))
    );
}

#[test]
fn tool_guard_bounds_pending_but_allows_more_than_capacity_sequentially() {
    let mut guard = ToolCorrelationGuard::default();
    let Some(v1::envelope::Body::Event(event)) = tool_event().body else {
        unreachable!()
    };
    let Some(v1::driver_event::Event::ToolCommand(base)) = event.event else {
        unreachable!()
    };
    for index in 1..=MAX_PENDING_TOOL_REQUESTS {
        let mut command = base.clone();
        command.request_id = bytes(u8::try_from(index).unwrap());
        assert_eq!(
            guard.observe_command(&command),
            Ok(ToolCorrelationDisposition::New)
        );
    }
    let mut overflow = base.clone();
    overflow.request_id = bytes(200);
    assert_eq!(
        guard.observe_command(&overflow),
        Err(ValidationError::Oversized("tool.pending_requests"))
    );
    for index in 1..=MAX_PENDING_TOOL_REQUESTS {
        guard.forget(&bytes(u8::try_from(index).unwrap()));
    }
    for index in 1..=200usize {
        let mut command = base.clone();
        command.request_id = bytes(u8::try_from(index).unwrap());
        assert_eq!(
            guard.observe_command(&command),
            Ok(ToolCorrelationDisposition::New)
        );
        guard.forget(&command.request_id);
    }
}

proptest::proptest! {
    #[test]
    fn malformed_input_never_bypasses_validation(input in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..1024)) {
        if let Ok(value) = v1::Envelope::decode(input.as_slice()) {
            let _ = value.validate();
        }
    }
}
