use navigator_driver_protocol::{sign_response, v1};
use prost::Message;
use std::fmt::Write;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").unwrap();
        output
    })
}

fn main() {
    use v1::driver_event::Event;
    use v1::envelope::Body;

    let responses = [
        (
            "describe",
            Body::DescribeResponse(v1::DescribeResponse::default()),
        ),
        ("start", Body::StartResponse(v1::StartResponse::default())),
        (
            "inspect",
            Body::InspectResponse(v1::InspectResponse::default()),
        ),
        (
            "deliver",
            Body::DeliverResponse(v1::DeliverResponse::default()),
        ),
        (
            "acceptance",
            Body::AcceptanceResponse(v1::AcceptanceResponse::default()),
        ),
        (
            "cancel",
            Body::CancelResponse(v1::CancelResponse::default()),
        ),
        ("stop", Body::StopResponse(v1::StopResponse::default())),
        (
            "remind",
            Body::RemindResponse(v1::RemindResponse::default()),
        ),
        (
            "hierarchy_result",
            Body::HierarchyResultResponse(v1::HierarchyResultResponse::default()),
        ),
        (
            "tool_result",
            Body::ToolResultResponse(v1::ToolResultResponse {
                in_reply_to: vec![6; 16],
                tool_request_id: vec![7; 16],
            }),
        ),
    ];
    for (name, body) in responses {
        emit(name, body);
    }
    for (name, event) in [
        ("event_ready", Event::Ready(v1::Ready::default())),
        (
            "event_acceptance",
            Event::Acceptance(v1::AcceptanceEvent::default()),
        ),
        ("event_report", Event::Report(v1::Report::default())),
        (
            "event_disconnected",
            Event::Disconnected(v1::Disconnected::default()),
        ),
        ("event_stopped", Event::Stopped(v1::StopResponse::default())),
        (
            "event_hierarchy",
            Event::HierarchyCommand(v1::HierarchyCommand::default()),
        ),
        ("event_tool", Event::ToolCommand(v1::ToolCommand::default())),
    ] {
        emit(
            name,
            Body::Event(v1::DriverEvent {
                event_id: vec![4; 16],
                instance: None,
                sequence: 7,
                event: Some(event),
                in_reply_to: vec![5; 16],
            }),
        );
    }
    emit(
        "observe_tool",
        Body::ObserveResponse(v1::ObserveResponse {
            result: Some(v1::observe_response::Result::Event(Box::new(
                v1::DriverEvent {
                    event_id: vec![4; 16],
                    instance: None,
                    sequence: 7,
                    event: Some(Event::ToolCommand(v1::ToolCommand::default())),
                    in_reply_to: vec![5; 16],
                },
            ))),
            in_reply_to: vec![6; 16],
        }),
    );
}

fn emit(name: &str, body: v1::envelope::Body) {
    let mut envelope = v1::Envelope {
        envelope_id: vec![1; 16],
        response_authenticator: Vec::new(),
        response_to_request_id: vec![2; 16],
        body: Some(body),
    };
    sign_response(b"0123456789abcdef0123456789abcdef", &mut envelope).unwrap();
    let authenticator = envelope.response_authenticator.clone();
    envelope.response_authenticator.clear();
    println!(
        "{name} {} {}",
        hex(&envelope.encode_to_vec()),
        hex(&authenticator)
    );
}
