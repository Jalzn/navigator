import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import {
  Acceptance,
  AuthenticationSchema,
  CancelDisposition,
  CancelRequestSchema,
  DescribeRequestSchema,
  DeliverRequestSchema,
  DriverEventSchema,
  EnvelopeSchema,
  FailureCode,
  HierarchyCommandSchema,
  HierarchyResultRequestSchema,
  InspectRequestSchema,
  InstanceIdentitySchema,
  InstanceState,
  MutationMetadataSchema,
  ObserveRequestSchema,
  RequestMetadataSchema,
  StartRequestSchema,
  SpawnChildCommandSchema,
  SpawnChildResultSchema,
  StopDisposition,
  StopRequestSchema,
  ToolArtifactReferenceSchema,
  ToolCallResultSchema,
  ToolResultRequestSchema,
  type Envelope,
  type DeliverRequest,
  type InstanceIdentity,
  type RequestMetadata,
} from "@navigator/driver-protocol/gen/navigator/driver/v1/driver_pb.js";
import { AcceptanceJournal, PiAdapter, type PiSession } from "../src/adapter.js";
import { PiDriverServer, validateToolSuccess } from "../src/server.js";
import type { NavigatorToolBridge } from "../src/tools.js";

class Session implements PiSession {
  prompts: string[] = [];
  aborts = 0;
  disposals = 0;
  abortGate: Promise<void> = Promise.resolve();
  async prompt(value: string): Promise<void> { this.prompts.push(value); }
  async steer(value: string): Promise<void> { this.prompts.push(value); }
  async abort(): Promise<void> { this.aborts += 1; await this.abortGate; }
  dispose(): void { this.disposals += 1; }
  subscribe(): () => void { return () => undefined; }
  lastAssistantText(): string { return ""; }
}

function metadata(envelope: Envelope): RequestMetadata {
  if (envelope.body.case === "describeRequest" || envelope.body.case === "inspectRequest" || envelope.body.case === "observeRequest") return envelope.body.value.metadata!;
  if (envelope.body.case === "startRequest" || envelope.body.case === "deliverRequest" || envelope.body.case === "cancelRequest" || envelope.body.case === "stopRequest" || envelope.body.case === "toolResultRequest") {
    return envelope.body.value.metadata!.request!;
  }
  throw new Error("unsupported test request");
}

function length(hmac: ReturnType<typeof createHmac>, value: Uint8Array): void {
  const size = Buffer.alloc(8);
  size.writeBigUInt64BE(BigInt(value.length));
  hmac.update(size).update(value);
}

function protoVarint(value: number): Buffer {
  const bytes: number[] = [];
  do { let byte = value & 0x7f; value = Math.floor(value / 128); if (value !== 0) byte |= 0x80; bytes.push(byte); } while (value !== 0);
  return Buffer.from(bytes);
}
function protoBytes(tag: number, value: Uint8Array): Buffer {
  return Buffer.concat([protoVarint((tag << 3) | 2), protoVarint(value.length), Buffer.from(value)]);
}

function sign(secret: Buffer, envelope: Envelope, participant = new Uint8Array(), launch = new Uint8Array()): void {
  const request = metadata(envelope);
  const auth = request.authentication!;
  const canonical = fromBinary(EnvelopeSchema, toBinary(EnvelopeSchema, envelope));
  metadata(canonical).authentication!.authenticator = new Uint8Array();
  metadata(canonical).authentication!.requestDigest = new Uint8Array();
  const canonicalBytes = canonical.body.case === "toolResultRequest"
    ? Buffer.concat([protoBytes(25, toBinary(ToolResultRequestSchema, canonical.body.value)), protoBytes(20, canonical.envelopeId)])
    : toBinary(EnvelopeSchema, canonical);
  auth.requestDigest = createHash("sha256").update(canonicalBytes).digest();
  const hmac = createHmac("sha256", secret).update("navigator.driver.v1\0");
  for (const value of [
    envelope.envelopeId, request.requestId, auth.keyId, auth.nonce, auth.requestDigest, participant, launch,
  ]) length(hmac, value);
  const protocol = Buffer.alloc(4);
  protocol.writeUInt32BE(request.protocolVersion);
  const expiry = Buffer.alloc(8);
  expiry.writeBigInt64BE(auth.expiresUnixMs);
  auth.authenticator = hmac.update(protocol).update(expiry).digest();
}

function requestMetadata(secret: Buffer, value: number): RequestMetadata {
  return create(RequestMetadataSchema, {
    protocolVersion: 1,
    requestId: Buffer.alloc(16, value),
    authentication: create(AuthenticationSchema, {
      keyId: createHash("sha256").update(secret).digest().subarray(0, 16),
      nonce: Buffer.alloc(16, value + 10),
      expiresUnixMs: BigInt(Date.now() + 30_000),
    }),
  });
}

test("real Tool result handler preserves complete artifacts and rejects malformed mutations", async () => {
  const root = await mkdtemp(join(tmpdir(), "navigator-pi-tool-result-"));
  const secret = Buffer.alloc(32, 61); const driverId = Buffer.alloc(16, 62);
  const participant = Buffer.alloc(16, 63); const attempt = Buffer.alloc(16, 64);
  const instanceId = Buffer.alloc(16, 65); const sessionId = Buffer.alloc(16, 66);
  const operationId = Buffer.alloc(16, 67); const native = new Session();
  let releasePrompt!: () => void;
  native.prompt = async (value: string) => { native.prompts.push(value); await new Promise<void>((resolve) => { releasePrompt = resolve; }); };
  let bridge!: NavigatorToolBridge;
  const catalog = { navigator_tool_catalog: [{
    registration_id: "44".repeat(16), name: "Records.Lookup", version: "V1",
    input_schema: { type: "object", additionalProperties: false },
  }] };
  const server = new PiDriverServer(secret, driverId, async (binding, _configuration, captured) => {
    bridge = captured;
    return new PiAdapter(binding, native, await AcceptanceJournal.open(join(root, "journal"), binding), captured);
  });
  const identity = create(InstanceIdentitySchema, { driverId, participantId: participant, launchAttemptId: attempt, instanceId, sessionId, ownershipEpoch: 8n });
  const start = create(EnvelopeSchema, { envelopeId: Buffer.alloc(16, 68), body: { case: "startRequest", value: create(StartRequestSchema, {
    metadata: create(MutationMetadataSchema, { request: requestMetadata(secret, 68) }), participantId: participant,
    launchAttemptId: attempt, instanceId, sessionId, ownershipEpoch: 8n, trustedConfiguration: Buffer.from(JSON.stringify(catalog)),
  }) } });
  sign(secret, start, participant, attempt); await server.handle(toBinary(EnvelopeSchema, start));
  const deliver = create(EnvelopeSchema, { envelopeId: Buffer.alloc(16, 69), body: { case: "deliverRequest", value: create(DeliverRequestSchema, {
    metadata: create(MutationMetadataSchema, { request: requestMetadata(secret, 69) }), instance: identity,
    messageId: Buffer.alloc(16, 70), operationId, deliveryAttemptId: Buffer.alloc(16, 71), payload: Buffer.from("blocked prompt"),
  }) } });
  sign(secret, deliver, participant, attempt); await server.handle(toBinary(EnvelopeSchema, deliver));
  while (native.prompts.length === 0) await new Promise((resolve) => setTimeout(resolve, 1));
  const tool = bridge.tools().find((value) => value.name === "Records.Lookup")!;
  const artifact = create(ToolArtifactReferenceSchema, {
    artifactId: Buffer.alloc(16, 72), sessionId, creatorParticipantId: participant,
    creatorOperationId: operationId, mediaType: "application/octet-stream", size: 3n, sha256: Buffer.alloc(32, 73),
  });
  let seed = 80;
  const roundtrip = async (callId: string, artifacts: typeof artifact[]) => {
    const pending = (tool.execute as (...args: unknown[]) => Promise<unknown>)(callId, {});
    const requestId = createHash("sha256").update("navigator.pi.tool.request\0").update(operationId).update(callId).digest().subarray(0, 16);
    requestId[6] = (requestId[6]! & 0x0f) | 0x40; requestId[8] = (requestId[8]! & 0x3f) | 0x80;
    const request = create(EnvelopeSchema, { envelopeId: Buffer.alloc(16, seed), body: { case: "toolResultRequest", value: create(ToolResultRequestSchema, {
      metadata: create(MutationMetadataSchema, { request: requestMetadata(secret, seed++) }), instance: identity, toolRequestId: requestId,
      result: { case: "success", value: create(ToolCallResultSchema, { output: Buffer.from("{}"), artifacts }) },
    }) } });
    sign(secret, request, participant, attempt);
    const response = fromBinary(EnvelopeSchema, await server.handle(toBinary(EnvelopeSchema, request)));
    return { pending, response };
  };
  const zero = structuredClone(artifact); zero.creatorParticipantId = Buffer.alloc(16);
  assert.throws(() => validateToolSuccess({ output: Buffer.from("{}"), artifacts: [zero] }));
  assert.throws(() => validateToolSuccess({ output: Buffer.from("{}"), artifacts: Array.from({ length: 33 }, () => artifact) }));
  const badHash = structuredClone(artifact); badHash.sha256 = Buffer.alloc(31);
  assert.throws(() => validateToolSuccess({ output: Buffer.from("{}"), artifacts: [badHash] }));
  const valid = await roundtrip("valid", [artifact]);
  assert.equal(valid.response.body.case, "toolResultResponse");
  const observed = await valid.pending as { details: { artifacts: unknown[] } };
  assert.deepEqual(observed.details.artifacts, [{ artifactId: "48".repeat(16), sessionId: "42".repeat(16), creatorParticipantId: "3f".repeat(16), creatorOperationId: "43".repeat(16), mediaType: "application/octet-stream", size: "3", sha256: "49".repeat(32) }]);
  releasePrompt(); await server.stop();
});

test("authenticated generated envelopes bind Start identity and exact Deliver acceptance", async () => {
  const root = await mkdtemp(join(tmpdir(), "navigator-pi-wire-"));
  const secret = Buffer.alloc(32, 9);
  const driverId = Buffer.alloc(16, 1);
  const native = new Session();
  const server = new PiDriverServer(secret, driverId, async (binding) => new PiAdapter(
    binding,
    native,
    await AcceptanceJournal.open(join(root, "journal"), binding),
  ), ["durable-acceptance.v1"]);

  const describe = create(EnvelopeSchema, {
    envelopeId: Buffer.alloc(16, 2),
    body: { case: "describeRequest", value: create(DescribeRequestSchema, {
      metadata: requestMetadata(secret, 2),
    }) },
  });
  sign(secret, describe);
  const described = fromBinary(EnvelopeSchema, await server.handle(toBinary(EnvelopeSchema, describe)));
  assert.equal(described.body.case, "describeResponse");
  assert.equal(described.responseAuthenticator.length, 32);
  await assert.rejects(server.handle(toBinary(EnvelopeSchema, describe)), /replay/,
    "pre-auth replay must close the request without a signed Failure");

  const unauthenticatedStop = create(EnvelopeSchema, {
    envelopeId: Buffer.alloc(16, 41),
    body: { case: "stopRequest", value: create(StopRequestSchema, {
      metadata: create(MutationMetadataSchema, { request: requestMetadata(secret, 41) }),
      instance: create(InstanceIdentitySchema, {
        driverId, sessionId: Buffer.alloc(16, 42), participantId: Buffer.alloc(16, 43),
        launchAttemptId: Buffer.alloc(16, 44), instanceId: Buffer.alloc(16, 45), ownershipEpoch: 1n,
      }),
    }) },
  });
  sign(secret, unauthenticatedStop, Buffer.alloc(16, 43), Buffer.alloc(16, 44));
  metadata(unauthenticatedStop).authentication!.authenticator[0]! ^= 0xff;
  const poisonedFrame = toBinary(EnvelopeSchema, unauthenticatedStop);
  for (let index = 0; index < 1025; index += 1) {
    await assert.rejects(server.handle(poisonedFrame), /authentication tag mismatch/);
  }

  const participant = Buffer.alloc(16, 3);
  const attempt = Buffer.alloc(16, 4);
  const instance = Buffer.alloc(16, 5);
  const sessionId = Buffer.alloc(16, 6);
  const start = create(EnvelopeSchema, {
    envelopeId: Buffer.alloc(16, 7),
    body: { case: "startRequest", value: create(StartRequestSchema, {
      metadata: create(MutationMetadataSchema, { request: requestMetadata(secret, 7) }),
      participantId: participant,
      launchAttemptId: attempt,
      instanceId: instance,
      sessionId,
      ownershipEpoch: 8n,
      trustedConfiguration: Buffer.from('{"navigator_tool_catalog":[]}'),
    }) },
  });
  sign(secret, start, participant, attempt);
  const started = fromBinary(EnvelopeSchema, await server.handle(toBinary(EnvelopeSchema, start)));
  assert.equal(started.body.case, "startResponse");
  const bound = started.body.case === "startResponse" && started.body.value.result.case === "success"
    ? started.body.value.result.value.instance : undefined;
  assert.ok(bound);

  const deliver = create(EnvelopeSchema, {
    envelopeId: Buffer.alloc(16, 9),
    body: { case: "deliverRequest", value: create(DeliverRequestSchema, {
      metadata: create(MutationMetadataSchema, { request: requestMetadata(secret, 9) }),
      instance: bound,
      messageId: Buffer.alloc(16, 10),
      operationId: Buffer.alloc(16, 11),
      deliveryAttemptId: Buffer.alloc(16, 12),
      payload: Buffer.from("worker instruction"),
    }) },
  });
  sign(secret, deliver, participant, attempt);
  const delivered = fromBinary(EnvelopeSchema, await server.handle(toBinary(EnvelopeSchema, deliver)));
  assert.equal(delivered.body.case, "deliverResponse");
  assert.deepEqual(native.prompts, ["worker instruction"]);

  const makeCancel = (seed: number): Envelope => {
    const request = create(EnvelopeSchema, { envelopeId: Buffer.alloc(16, seed), body: { case: "cancelRequest", value: create(CancelRequestSchema, {
      metadata: create(MutationMetadataSchema, { request: requestMetadata(secret, seed) }),
      instance: fromBinary(InstanceIdentitySchema, toBinary(InstanceIdentitySchema, bound!)),
      operationId: Buffer.alloc(16, 11),
    }) } });
    sign(secret, request, participant, attempt);
    return request;
  };
  for (const [index, mutate] of [
    (identity: InstanceIdentity) => { identity.driverId = Buffer.alloc(16, 91); },
    (identity: InstanceIdentity) => { identity.sessionId = Buffer.alloc(16, 92); },
    (identity: InstanceIdentity) => { identity.participantId = Buffer.alloc(16, 93); },
    (identity: InstanceIdentity) => { identity.launchAttemptId = Buffer.alloc(16, 94); },
    (identity: InstanceIdentity) => { identity.instanceId = Buffer.alloc(16, 95); },
    (identity: InstanceIdentity) => { identity.ownershipEpoch += 1n; },
  ].entries()) {
    const forged = makeCancel(130 + index);
    if (forged.body.case !== "cancelRequest" || forged.body.value.instance === undefined) throw new Error("test Cancel identity missing");
    mutate(forged.body.value.instance);
    sign(secret, forged, Buffer.from(forged.body.value.instance.participantId), Buffer.from(forged.body.value.instance.launchAttemptId));
    const failure = fromBinary(EnvelopeSchema, await server.handle(toBinary(EnvelopeSchema, forged)));
    const code = failure.body.case === "cancelResponse" && failure.body.value.result.case === "failure"
      ? failure.body.value.result.value.code : 0;
    assert.equal(code, FailureCode.CONFLICT);
    if (failure.body.case === "cancelResponse" && failure.body.value.result.case === "failure") {
      assert.equal(failure.body.value.result.value.message, "request conflicts with driver state");
      assert.equal(failure.body.value.result.value.message.includes(root), false, "Failure leaked a private path");
    }
    assert.equal(failure.responseAuthenticator.length, 32);
  }
  let releaseAbort!: () => void;
  native.abortGate = new Promise<void>((resolve) => { releaseAbort = resolve; });
  const concurrentCancels = [17, 18].map((seed) => server.handle(toBinary(EnvelopeSchema, makeCancel(seed))));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(native.aborts, 1, "concurrent Cancel did not share the in-flight abort");
  releaseAbort();
  for (const response of await Promise.all(concurrentCancels)) {
    const cancelled = fromBinary(EnvelopeSchema, response);
    assert.equal(cancelled.body.case === "cancelResponse" && cancelled.body.value.result.case === "success"
      ? cancelled.body.value.result.value.disposition : 0, CancelDisposition.CANCEL_REQUESTED);
  }
  assert.equal(native.aborts, 1, "second Cancel request repeated the native abort effect");

  const semanticReplay = create(EnvelopeSchema, {
    envelopeId: Buffer.alloc(16, 13),
    body: { case: "deliverRequest", value: create(DeliverRequestSchema, {
      metadata: create(MutationMetadataSchema, { request: requestMetadata(secret, 13) }),
      instance: bound, messageId: Buffer.alloc(16, 10), operationId: Buffer.alloc(16, 11),
      deliveryAttemptId: Buffer.alloc(16, 12), payload: Buffer.from("worker instruction"),
    }) },
  });
  sign(secret, semanticReplay, participant, attempt);
  const replayed = fromBinary(EnvelopeSchema, await server.handle(toBinary(EnvelopeSchema, semanticReplay)));
  assert.equal(replayed.body.case === "deliverResponse" && replayed.body.value.result.case === "success"
    ? replayed.body.value.result.value.acceptance : 0, Acceptance.ACCEPTED);
  assert.deepEqual(native.prompts, ["worker instruction"], "new causal request reinjected the same Message");

  for (const [seed, mutate] of [
    [14, (value: DeliverRequest) => { value.payload = Buffer.from("changed"); }],
    [15, (value: DeliverRequest) => { value.operationId = Buffer.alloc(16, 99); }],
    [16, (value: DeliverRequest) => { value.deliveryAttemptId = Buffer.alloc(16, 98); }],
  ] as const) {
    const conflict = fromBinary(EnvelopeSchema, toBinary(EnvelopeSchema, semanticReplay));
    conflict.envelopeId = Buffer.alloc(16, seed);
    if (conflict.body.case !== "deliverRequest") throw new Error("test Deliver body missing");
    conflict.body.value.metadata = create(MutationMetadataSchema, { request: requestMetadata(secret, seed) });
    mutate(conflict.body.value);
    sign(secret, conflict, participant, attempt);
    const rejected = fromBinary(EnvelopeSchema, await server.handle(toBinary(EnvelopeSchema, conflict)));
    assert.equal(rejected.body.case === "deliverResponse" ? rejected.body.value.result.case : "", "failure");
    if (rejected.body.case !== "deliverResponse" || rejected.body.value.result.case !== "failure") throw new Error("missing Deliver failure");
    assert.equal(rejected.body.value.result.value.code, FailureCode.CONFLICT);
    assert.equal(rejected.body.value.result.value.message, "request conflicts with driver state");
    assert.equal(rejected.responseAuthenticator.length, 32);
  }
  assert.deepEqual(native.prompts, ["worker instruction"]);

  const observe = (envelopeByte: number, afterSequence: bigint): Envelope => {
    const request = create(EnvelopeSchema, {
      envelopeId: Buffer.alloc(16, envelopeByte),
      body: { case: "observeRequest", value: create(ObserveRequestSchema, {
        metadata: requestMetadata(secret, envelopeByte), instance: bound, afterSequence,
      }) },
    });
    sign(secret, request, participant, attempt);
    return request;
  };
  const alreadyDurable = fromBinary(EnvelopeSchema, await server.handle(toBinary(EnvelopeSchema, observe(20, 1n))));
  assert.equal(alreadyDurable.body.case, "observeResponse");
  if (alreadyDurable.body.case === "observeResponse" && alreadyDurable.body.value.result.case === "event") assert.equal(alreadyDurable.body.value.result.value.sequence, 2n);

  let longPollSettled = false;
  const waiting = server.handle(toBinary(EnvelopeSchema, observe(21, 2n))).then((value) => {
    longPollSettled = true;
    return value;
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(longPollSettled, false, "empty Observe closed instead of waiting");
  const secondDeliver = create(EnvelopeSchema, {
    envelopeId: Buffer.alloc(16, 22),
    body: { case: "deliverRequest", value: create(DeliverRequestSchema, {
      metadata: create(MutationMetadataSchema, { request: requestMetadata(secret, 22) }), instance: bound,
      messageId: Buffer.alloc(16, 23), operationId: Buffer.alloc(16, 11),
      deliveryAttemptId: Buffer.alloc(16, 24), payload: Buffer.from("second instruction"),
    }) },
  });
  sign(secret, secondDeliver, participant, attempt);
  await server.handle(toBinary(EnvelopeSchema, secondDeliver));
  const awakened = fromBinary(EnvelopeSchema, await waiting);
  assert.equal(awakened.body.case, "observeResponse");
  if (awakened.body.case === "observeResponse" && awakened.body.value.result.case === "event") {
    assert.equal(awakened.body.value.result.value.sequence, 3n);
    assert.deepEqual(Buffer.from(awakened.body.value.result.value.inReplyTo), Buffer.from(secondDeliver.envelopeId));
  }

  const blocked = Array.from({ length: 64 }, (_, index) =>
    server.handle(toBinary(EnvelopeSchema, observe(40 + index, 3n))));
  await new Promise((resolve) => setImmediate(resolve));
  await assert.rejects(() => server.handle(toBinary(EnvelopeSchema, observe(120, 3n))), /capacity/);
  const makeStop = (seed: number): Envelope => {
    const request = create(EnvelopeSchema, { envelopeId: Buffer.alloc(16, seed), body: { case: "stopRequest", value: create(StopRequestSchema, {
      metadata: create(MutationMetadataSchema, { request: requestMetadata(secret, seed) }), instance: bound,
    }) } });
    sign(secret, request, participant, attempt);
    return request;
  };
  const firstStop = makeStop(121);
  const confirmedBytes = await server.handle(toBinary(EnvelopeSchema, firstStop));
  const confirmed = fromBinary(EnvelopeSchema, confirmedBytes);
  assert.equal(confirmed.body.case === "stopResponse" && confirmed.body.value.result.case === "success"
    ? confirmed.body.value.result.value.disposition : 0, StopDisposition.STOPPED_CONFIRMED);
  assert.deepEqual([native.aborts, native.disposals], [2, 1]);
  assert.deepEqual(await server.handle(toBinary(EnvelopeSchema, firstStop)), confirmedBytes,
    "exact Stop replay did not use the confirmed response ledger");
  assert.deepEqual([native.aborts, native.disposals], [2, 1]);
  const laterStop = fromBinary(EnvelopeSchema, await server.handle(toBinary(EnvelopeSchema, makeStop(122))));
  assert.equal(laterStop.body.case === "stopResponse" && laterStop.body.value.result.case === "success"
    ? laterStop.body.value.result.value.disposition : 0, StopDisposition.ALREADY_STOPPED);
  assert.deepEqual([native.aborts, native.disposals], [2, 1]);
  const outcomes = await Promise.allSettled(blocked);
  assert.ok(outcomes.every((outcome) => outcome.status === "rejected"));
});

test("reopen with a lost hierarchy waiter is uncertain and blocks new delivery", async () => {
  const root = await mkdtemp(join(tmpdir(), "navigator-pi-hierarchy-reopen-"));
  const secret = Buffer.alloc(32, 29);
  const driverId = Buffer.alloc(16, 1);
  const participant = Buffer.alloc(16, 3);
  const attempt = Buffer.alloc(16, 4);
  const instanceId = Buffer.alloc(16, 5);
  const sessionId = Buffer.alloc(16, 6);
  const binding = {
    driverId: driverId.toString("hex"), participantId: participant.toString("hex"),
    launchAttemptId: attempt.toString("hex"), instanceId: instanceId.toString("hex"),
    sessionId: sessionId.toString("hex"), ownershipEpoch: 8n,
    trustedConfigurationDigest: createHash("sha256").update('{"navigator_tool_catalog":[]}').digest("hex"),
    capabilityProfileDigest: createHash("sha256").update("[]").digest("hex"),
  };
  const identity = { driverId, participantId: participant, launchAttemptId: attempt, instanceId, sessionId, ownershipEpoch: 8n };
  const path = join(root, "journal");
  const seeded = await AcceptanceJournal.open(path, binding);
  const hierarchy = create(DriverEventSchema, {
    eventId: Buffer.alloc(16, 20), instance: create(InstanceIdentitySchema, identity), sequence: 1n,
    inReplyTo: Buffer.alloc(16, 24),
    event: { case: "hierarchyCommand", value: create(HierarchyCommandSchema, {
      requestId: Buffer.alloc(16, 21),
      command: { case: "spawnChild", value: create(SpawnChildCommandSchema, {
        templateId: Buffer.alloc(16, 22), taskInput: Buffer.from("{}"), grantId: Buffer.alloc(16, 23),
      }) },
    }) },
  });
  seeded.appendEvent(1n, Buffer.from(toBinary(DriverEventSchema, hierarchy)).toString("base64"));
  seeded.close();
  const recoveredNative = new Session();
  const server = new PiDriverServer(secret, driverId, async (loaded) => new PiAdapter(loaded, recoveredNative, await AcceptanceJournal.open(path, loaded)));
  const start = create(EnvelopeSchema, { envelopeId: Buffer.alloc(16, 7), body: { case: "startRequest", value: create(StartRequestSchema, {
    metadata: create(MutationMetadataSchema, { request: requestMetadata(secret, 7) }), participantId: participant,
    launchAttemptId: attempt, instanceId, sessionId, ownershipEpoch: 8n, trustedConfiguration: Buffer.from('{"navigator_tool_catalog":[]}'),
  }) } });
  sign(secret, start, participant, attempt);
  await server.handle(toBinary(EnvelopeSchema, start));
  const inspect = create(EnvelopeSchema, { envelopeId: Buffer.alloc(16, 30), body: { case: "inspectRequest", value: create(InspectRequestSchema, {
    metadata: requestMetadata(secret, 30), instance: create(InstanceIdentitySchema, identity),
  }) } });
  sign(secret, inspect, participant, attempt);
  const inspected = fromBinary(EnvelopeSchema, await server.handle(toBinary(EnvelopeSchema, inspect)));
  assert.equal(inspected.body.case === "inspectResponse" && inspected.body.value.result.case === "success"
    ? inspected.body.value.result.value.state : 0, InstanceState.INSTANCE_UNCERTAIN);
  const deliver = create(EnvelopeSchema, { envelopeId: Buffer.alloc(16, 31), body: { case: "deliverRequest", value: create(DeliverRequestSchema, {
    metadata: create(MutationMetadataSchema, { request: requestMetadata(secret, 31) }), instance: create(InstanceIdentitySchema, identity),
    messageId: Buffer.alloc(16, 32), operationId: Buffer.alloc(16, 33), deliveryAttemptId: Buffer.alloc(16, 34), payload: Buffer.from("must not run"),
  }) } });
  sign(secret, deliver, participant, attempt);
  const blockedDelivery = fromBinary(EnvelopeSchema, await server.handle(toBinary(EnvelopeSchema, deliver)));
  assert.equal(blockedDelivery.body.case === "deliverResponse" ? blockedDelivery.body.value.result.case : "", "failure");
  await assert.rejects(() => server.interactiveLine("must not spawn"), /requires hierarchy recovery/);
  assert.deepEqual(recoveredNative.prompts, []);
  await server.stop();

  // A durable result suppresses command republication, but without proof that
  // Pi persisted the tool result the crash window remains uncertain.
  const commandSemantic = Buffer.from(toBinary(DriverEventSchema, hierarchy)).toString("base64");
  const resultSemantic = Buffer.from(toBinary(HierarchyResultRequestSchema, create(HierarchyResultRequestSchema, {
    instance: create(InstanceIdentitySchema, identity), hierarchyRequestId: Buffer.alloc(16, 21),
    result: { case: "spawned", value: create(SpawnChildResultSchema, { participantId: Buffer.alloc(16, 25), operationId: Buffer.alloc(16, 26), inputMessageId: Buffer.alloc(16, 27) }) },
  }))).toString("base64");
  const acknowledged = await AcceptanceJournal.open(path, binding);
  acknowledged.recordHierarchyResult(Buffer.alloc(16, 21).toString("hex"), commandSemantic, resultSemantic);
  acknowledged.close();
  const postAckNative = new Session();
  const postAck = new PiDriverServer(secret, driverId, async (loaded) => new PiAdapter(
    loaded, postAckNative, await AcceptanceJournal.open(path, loaded),
  ));
  const restart = create(EnvelopeSchema, { envelopeId: Buffer.alloc(16, 40), body: { case: "startRequest", value: create(StartRequestSchema, {
    metadata: create(MutationMetadataSchema, { request: requestMetadata(secret, 40) }), participantId: participant,
    launchAttemptId: attempt, instanceId, sessionId, ownershipEpoch: 8n, trustedConfiguration: Buffer.from('{"navigator_tool_catalog":[]}'),
  }) } });
  sign(secret, restart, participant, attempt);
  await postAck.handle(toBinary(EnvelopeSchema, restart));
  const postAckInspect = create(EnvelopeSchema, { envelopeId: Buffer.alloc(16, 41), body: { case: "inspectRequest", value: create(InspectRequestSchema, {
    metadata: requestMetadata(secret, 41), instance: create(InstanceIdentitySchema, identity),
  }) } });
  sign(secret, postAckInspect, participant, attempt);
  const healthy = fromBinary(EnvelopeSchema, await postAck.handle(toBinary(EnvelopeSchema, postAckInspect)));
  assert.equal(healthy.body.case === "inspectResponse" && healthy.body.value.result.case === "success"
    ? healthy.body.value.result.value.state : 0, InstanceState.INSTANCE_UNCERTAIN);
  const postAckObserve = create(EnvelopeSchema, { envelopeId: Buffer.alloc(16, 42), body: { case: "observeRequest", value: create(ObserveRequestSchema, {
    metadata: requestMetadata(secret, 42), instance: create(InstanceIdentitySchema, identity), afterSequence: 0n,
  }) } });
  sign(secret, postAckObserve, participant, attempt);
  const observed = fromBinary(EnvelopeSchema, await postAck.handle(toBinary(EnvelopeSchema, postAckObserve)));
  assert.notEqual(observed.body.case === "observeResponse" && observed.body.value.result.case === "event"
    ? observed.body.value.result.value.event.case : "", "hierarchyCommand");
  const blockedAfterAck = create(EnvelopeSchema, { envelopeId: Buffer.alloc(16, 43), body: { case: "deliverRequest", value: create(DeliverRequestSchema, {
    metadata: create(MutationMetadataSchema, { request: requestMetadata(secret, 43) }), instance: create(InstanceIdentitySchema, identity),
    messageId: Buffer.alloc(16, 44), operationId: Buffer.alloc(16, 45), deliveryAttemptId: Buffer.alloc(16, 46), payload: Buffer.from("must remain blocked"),
  }) } });
  sign(secret, blockedAfterAck, participant, attempt);
  const postAckBlocked = fromBinary(EnvelopeSchema, await postAck.handle(toBinary(EnvelopeSchema, blockedAfterAck)));
  assert.equal(postAckBlocked.body.case === "deliverResponse" ? postAckBlocked.body.value.result.case : "", "failure");
  await postAck.stop();
});

test("concurrent Start is exactly-one and a conflicting loser never constructs Pi", async () => {
  const root = await mkdtemp(join(tmpdir(), "navigator-pi-start-race-"));
  const secret = Buffer.alloc(32, 19);
  let factories = 0;
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const server = new PiDriverServer(secret, Buffer.alloc(16, 1), async (binding) => {
    factories += 1;
    await gate;
    return new PiAdapter(binding, new Session(), await AcceptanceJournal.open(join(root, `journal-${binding.instanceId}`), binding));
  });
  const makeStart = (seed: number, requestSeed = seed + 2, configuration = '{"navigator_tool_catalog":[]}'): Envelope => {
    const participant = Buffer.alloc(16, seed);
    const attempt = Buffer.alloc(16, seed + 1);
    const envelope = create(EnvelopeSchema, {
      envelopeId: Buffer.alloc(16, requestSeed),
      body: { case: "startRequest", value: create(StartRequestSchema, {
        metadata: create(MutationMetadataSchema, { request: requestMetadata(secret, requestSeed) }),
        participantId: participant,
        launchAttemptId: attempt,
        instanceId: Buffer.alloc(16, seed + 3),
        sessionId: Buffer.alloc(16, seed + 4),
        ownershipEpoch: 1n,
        trustedConfiguration: Buffer.from(configuration),
      }) },
    });
    sign(secret, envelope, participant, attempt);
    return envelope;
  };
  const winner = server.handle(toBinary(EnvelopeSchema, makeStart(30)));
  await new Promise((resolve) => setImmediate(resolve));
  const loser = server.handle(toBinary(EnvelopeSchema, makeStart(60)));
  release();
  assert.equal(fromBinary(EnvelopeSchema, await winner).body.case, "startResponse");
  const loserResponse = fromBinary(EnvelopeSchema, await loser);
  assert.equal(loserResponse.body.case === "startResponse" ? loserResponse.body.value.result.case : "", "failure");
  assert.equal(factories, 1);
  const semanticConflict = fromBinary(EnvelopeSchema, await server.handle(toBinary(EnvelopeSchema, makeStart(30, 90, "{\"changed\":true}"))));
  assert.equal(semanticConflict.body.case === "startResponse" ? semanticConflict.body.value.result.case : "", "failure");
  assert.equal(factories, 1);
  await server.stop();
});
