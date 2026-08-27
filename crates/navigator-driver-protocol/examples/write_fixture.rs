use navigator_driver_protocol::{ID_BYTES, PROTOCOL_V1, v1};
use prost::Message;

fn bytes(value: u8) -> Vec<u8> {
    vec![value; ID_BYTES]
}

fn main() {
    let envelope = v1::Envelope {
        envelope_id: bytes(6),
        response_authenticator: Vec::new(),
        response_to_request_id: Vec::new(),
        body: Some(v1::envelope::Body::StartRequest(v1::StartRequest {
            metadata: Some(v1::MutationMetadata {
                request: Some(v1::RequestMetadata {
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
                }),
            }),
            participant_id: bytes(7),
            launch_attempt_id: bytes(8),
            instance_id: bytes(10),
            trusted_configuration: b"deterministic".to_vec(),
            session_id: bytes(9),
            ownership_epoch: 7,
        })),
    };
    std::fs::create_dir_all("fixtures").unwrap();
    std::fs::write("fixtures/start-v1.bin", envelope.encode_to_vec()).unwrap();
}
