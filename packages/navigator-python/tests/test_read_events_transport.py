import grpc
import pytest

from navigator._transport.navigator.consumer.v1 import consumer_pb2
from navigator._transport.navigator.consumer.v1.consumer_pb2 import (
    EventPage,
    Failure,
    ReadEventsRequest,
    ReadEventsResponse,
    SessionEvent,
)
from navigator._transport.navigator.consumer.v1.consumer_pb2_grpc import (
    NavigatorConsumerServicer,
    NavigatorConsumerStub,
    add_NavigatorConsumerServicer_to_server,
)


def test_read_events_messages_and_unary_descriptor_are_runtime_importable() -> None:
    request = ReadEventsRequest(session_id=b"session", after_position=7, page_size=2)
    page = EventPage(
        events=[SessionEvent(position=8, event_type="OperationStarted")],
        has_more=True,
    )
    response = ReadEventsResponse(page=page)

    assert ReadEventsRequest.FromString(request.SerializeToString()) == request
    assert ReadEventsResponse.FromString(response.SerializeToString()) == response
    assert response.page == page

    method = consumer_pb2.DESCRIPTOR.services_by_name[
        "NavigatorConsumer"
    ].methods_by_name["ReadEvents"]
    assert method.input_type.full_name == "navigator.consumer.v1.ReadEventsRequest"
    assert method.output_type.full_name == "navigator.consumer.v1.ReadEventsResponse"
    assert method.client_streaming is False
    assert method.server_streaming is False
    assert len(method.input_type.fields) == 4
    assert len(method.output_type.fields) == 2
    assert method.input_type.fields_by_name["session_id"].is_repeated is False
    assert method.input_type.fields_by_name["page_size"].is_repeated is False
    assert method.output_type.fields_by_name["page"].message_type.full_name == (
        "navigator.consumer.v1.EventPage"
    )
    assert method.output_type.fields_by_name["failure"].message_type.full_name == (
        "navigator.consumer.v1.Failure"
    )
    event_page = consumer_pb2.EventPage.DESCRIPTOR
    assert event_page.fields_by_name["events"].is_repeated is True
    assert event_page.fields_by_name["has_more"].is_repeated is False


class _SyncUnaryCall:
    def __init__(self, request_serializer, response_deserializer):
        self.request_serializer = request_serializer
        self.response_deserializer = response_deserializer
        self.serialized_request = b""

    def __call__(self, request):
        self.serialized_request = self.request_serializer(request)
        wire_response = ReadEventsResponse(
            page=EventPage(events=[SessionEvent(position=12)], has_more=False)
        ).SerializeToString()
        return self.response_deserializer(wire_response)


class _RecordingSyncChannel:
    def __init__(self):
        self.unary_methods = {}

    def unary_unary(self, path, request_serializer, response_deserializer, **_kwargs):
        call = _SyncUnaryCall(request_serializer, response_deserializer)
        self.unary_methods[path] = call
        return call

    def unary_stream(self, *_args, **_kwargs):
        return object()

    def stream_stream(self, *_args, **_kwargs):
        return object()

    def stream_unary(self, *_args, **_kwargs):
        return object()


def test_read_events_sync_stub_uses_exact_path_and_wire_codecs() -> None:
    channel = _RecordingSyncChannel()
    stub = NavigatorConsumerStub(channel)
    request = ReadEventsRequest(session_id=b"session", after_position=11, page_size=1)

    response = stub.ReadEvents(request)

    path = "/navigator.consumer.v1.NavigatorConsumer/ReadEvents"
    assert path in channel.unary_methods
    call = channel.unary_methods[path]
    assert ReadEventsRequest.FromString(call.serialized_request) == request
    assert isinstance(response, ReadEventsResponse)
    assert response.page.events[0].position == 12
    assert response.page.has_more is False


class _ReadEventsServicer(NavigatorConsumerServicer):
    async def ReadEvents(self, request, context):
        assert isinstance(request, ReadEventsRequest)
        if request.after_position == 90:
            return ReadEventsResponse(
                failure=Failure(
                    code=consumer_pb2.FAILURE_CODE_AUTHORIZATION,
                    message="event access denied",
                    retry=consumer_pb2.RETRY_CLASS_NEVER,
                )
            )
        assert request.after_position == 40
        return ReadEventsResponse(
            page=EventPage(
                events=[SessionEvent(position=41, event_type="MessageAppended")],
                has_more=True,
            )
        )


@pytest.mark.asyncio
async def test_read_events_aio_stub_is_awaited_and_decodes_event_page() -> None:
    server = grpc.aio.server()
    add_NavigatorConsumerServicer_to_server(_ReadEventsServicer(), server)
    port = server.add_insecure_port("127.0.0.1:0")
    assert port != 0
    await server.start()
    channel = grpc.aio.insecure_channel(f"127.0.0.1:{port}")
    try:
        response = await NavigatorConsumerStub(channel).ReadEvents(
            ReadEventsRequest(session_id=b"session", after_position=40, page_size=1)
        )

        assert isinstance(response, ReadEventsResponse)
        assert response.HasField("page")
        assert response.page.has_more is True
        assert [(event.position, event.event_type) for event in response.page.events] == [
            (41, "MessageAppended")
        ]
    finally:
        await channel.close()
        await server.stop(grace=None)


@pytest.mark.asyncio
async def test_read_events_aio_stub_decodes_failure_outcome() -> None:
    server = grpc.aio.server()
    add_NavigatorConsumerServicer_to_server(_ReadEventsServicer(), server)
    port = server.add_insecure_port("127.0.0.1:0")
    assert port != 0
    await server.start()
    channel = grpc.aio.insecure_channel(f"127.0.0.1:{port}")
    try:
        response = await NavigatorConsumerStub(channel).ReadEvents(
            ReadEventsRequest(session_id=b"forbidden", after_position=90, page_size=1)
        )

        assert isinstance(response, ReadEventsResponse)
        assert response.HasField("failure")
        assert response.HasField("page") is False
        assert response.failure.code == consumer_pb2.FAILURE_CODE_AUTHORIZATION
        assert response.failure.retry == consumer_pb2.RETRY_CLASS_NEVER
        assert response.failure.message == "event access denied"
    finally:
        await channel.close()
        await server.stop(grace=None)
