import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fromBinary } from "@bufbuild/protobuf";
import { EnvelopeSchema } from "@navigator/driver-protocol/gen/navigator/driver/v1/driver_pb.js";
import { RequestAuthenticator } from "../src/auth.js";

test("response MAC matches Rust prost for every response envelope body", async () => {
  const fixture = await readFile(new URL("response-mac-rust-v1.txt", import.meta.url), "utf8");
  const authenticator = new RequestAuthenticator(Buffer.from("0123456789abcdef0123456789abcdef"));
  const seen = new Set<string>();
  for (const line of fixture.trim().split("\n")) {
    const [name, envelopeHex, macHex] = line.split(" ");
    const envelope = fromBinary(EnvelopeSchema, Buffer.from(envelopeHex!, "hex"));
    authenticator.signResponse(envelope);
    assert.equal(Buffer.from(envelope.responseAuthenticator).toString("hex"), macHex, name);
    seen.add(name!);
  }
  assert.deepEqual(seen, new Set([
    "describe", "start", "inspect", "deliver", "acceptance", "cancel", "stop", "remind",
    "hierarchy_result", "tool_result", "event_ready", "event_acceptance", "event_report", "event_disconnected",
    "event_stopped", "event_hierarchy", "event_tool", "observe_tool",
  ]));
  for (const line of fixture.trim().split("\n")) {
    const [name, envelopeHex, macHex] = line.split(" ");
    if (name !== "event_tool" && name !== "observe_tool" && name !== "tool_result") continue;
    const envelope = fromBinary(EnvelopeSchema, Buffer.from(envelopeHex!, "hex"));
    if (envelope.body.case === "event") envelope.body.value.inReplyTo[0]! ^= 0xff;
    else if (envelope.body.case === "observeResponse" && envelope.body.value.result.case === "event") {
      envelope.body.value.result.value.inReplyTo[0]! ^= 0xff;
    } else if (envelope.body.case === "toolResultResponse") {
      envelope.body.value.toolRequestId[0]! ^= 0xff;
    } else throw new Error("Tool fixture shape changed");
    authenticator.signResponse(envelope);
    assert.notEqual(Buffer.from(envelope.responseAuthenticator).toString("hex"), macHex, name);
  }
});
