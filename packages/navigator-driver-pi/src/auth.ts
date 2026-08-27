import { createHmac, createHash, timingSafeEqual } from "node:crypto";
import { fromBinary, toBinary } from "@bufbuild/protobuf";
import {
  EnvelopeSchema,
  DriverEventSchema,
  HierarchyResultRequestSchema,
  ToolResultRequestSchema,
  HierarchyResultResponseSchema,
  ToolResultResponseSchema,
  ObserveResponseSchema,
  type Envelope,
  type DriverEvent,
  type InstanceIdentity,
  type RequestMetadata,
} from "@navigator/driver-protocol/gen/navigator/driver/v1/driver_pb.js";

function metadata(envelope: Envelope): RequestMetadata | undefined {
  switch (envelope.body.case) {
    case "describeRequest":
    case "inspectRequest":
    case "acceptanceRequest":
    case "observeRequest":
      return envelope.body.value.metadata;
    case "startRequest":
    case "deliverRequest":
    case "cancelRequest":
    case "stopRequest":
    case "remindRequest":
    case "hierarchyResultRequest":
    case "toolResultRequest":
      return envelope.body.value.metadata?.request;
    default:
      return undefined;
  }
}

function identity(envelope: Envelope): InstanceIdentity | undefined {
  switch (envelope.body.case) {
    case "inspectRequest":
    case "deliverRequest":
    case "acceptanceRequest":
    case "cancelRequest":
    case "stopRequest":
    case "observeRequest":
    case "remindRequest":
    case "hierarchyResultRequest":
    case "toolResultRequest":
      return envelope.body.value.instance;
    default:
      return undefined;
  }
}

function scopes(envelope: Envelope): [Uint8Array, Uint8Array] {
  if (envelope.body.case === "startRequest") {
    return [envelope.body.value.participantId, envelope.body.value.launchAttemptId];
  }
  const value = identity(envelope);
  return value === undefined ? [new Uint8Array(), new Uint8Array()] : [value.participantId, value.launchAttemptId];
}

function lengthPrefixed(hmac: ReturnType<typeof createHmac>, value: Uint8Array): void {
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(value.length));
  hmac.update(length);
  hmac.update(value);
}

function varint(value: number): Buffer {
  const bytes: number[] = [];
  do { let byte = value & 0x7f; value = Math.floor(value / 128); if (value !== 0) byte |= 0x80; bytes.push(byte); } while (value !== 0);
  return Buffer.from(bytes);
}

function bytesField(tag: number, value: Uint8Array): Buffer {
  return Buffer.concat([varint((tag << 3) | 2), varint(value.length), Buffer.from(value)]);
}

function canonicalDriverEventBytes(value: DriverEvent): Buffer {
  const event = fromBinary(DriverEventSchema, toBinary(DriverEventSchema, value));
  if (event.event.case !== "hierarchyCommand" && event.event.case !== "toolCommand") {
    return Buffer.from(toBinary(DriverEventSchema, event));
  }
  const reply = event.inReplyTo;
  event.inReplyTo = new Uint8Array();
  return Buffer.concat([Buffer.from(toBinary(DriverEventSchema, event)), bytesField(9, reply)]);
}

function canonicalResponseBytes(envelope: Envelope): Uint8Array {
  // Rust prost preserves declaration order; protobuf-es emits numeric tag order.
  // These envelopes have later-declared body fields before tags 20/22 on the wire.
  const lateBody = envelope.body.case === "hierarchyResultResponse"
    ? [24, toBinary(HierarchyResultResponseSchema, envelope.body.value)] as const
    : envelope.body.case === "toolResultResponse"
      ? [26, toBinary(ToolResultResponseSchema, envelope.body.value)] as const
      : undefined;
  if (lateBody !== undefined) {
    return Buffer.concat([
      bytesField(lateBody[0], lateBody[1]),
      bytesField(20, envelope.envelopeId),
      bytesField(22, envelope.responseToRequestId),
    ]);
  }
  if (envelope.body.case === "observeResponse") {
    const response = fromBinary(ObserveResponseSchema, toBinary(ObserveResponseSchema, envelope.body.value));
    let resultBytes: Buffer;
    if (response.result.case === "event") resultBytes = bytesField(1, canonicalDriverEventBytes(response.result.value));
    else if (response.result.case === "noEvent") resultBytes = bytesField(2, new Uint8Array());
    else resultBytes = Buffer.alloc(0);
    const responseBytes = Buffer.concat([resultBytes, bytesField(3, response.inReplyTo)]);
    return Buffer.concat([
      bytesField(27, responseBytes),
      bytesField(20, envelope.envelopeId),
      bytesField(22, envelope.responseToRequestId),
    ]);
  }
  if (envelope.body.case !== "event") {
    return toBinary(EnvelopeSchema, envelope);
  }
  return Buffer.concat([
    bytesField(16, canonicalDriverEventBytes(envelope.body.value)),
    bytesField(20, envelope.envelopeId),
    bytesField(22, envelope.responseToRequestId),
  ]);
}

function canonicalRequestBytes(envelope: Envelope): Uint8Array {
  if (envelope.body.case === "toolResultRequest") return Buffer.concat([
    bytesField(25, toBinary(ToolResultRequestSchema, envelope.body.value)),
    bytesField(20, envelope.envelopeId),
  ]);
  if (envelope.body.case !== "hierarchyResultRequest") return toBinary(EnvelopeSchema, envelope);
  return Buffer.concat([
    bytesField(23, toBinary(HierarchyResultRequestSchema, envelope.body.value)),
    bytesField(20, envelope.envelopeId),
  ]);
}

export class RequestAuthenticator {
  readonly #secret: Buffer;
  readonly #keyId: Buffer;
  readonly #nonces = new Map<string, bigint>();

  constructor(secret: Uint8Array) {
    this.#secret = Buffer.from(secret);
    this.#keyId = createHash("sha256").update(secret).digest().subarray(0, 16);
  }

  verify(envelope: Envelope, nowUnixMs = Date.now()): void {
    for (const [nonce, expiry] of this.#nonces) {
      if (expiry <= BigInt(nowUnixMs)) this.#nonces.delete(nonce);
    }
    const request = metadata(envelope);
    const authentication = request?.authentication;
    if (request === undefined || authentication === undefined) throw new Error("missing authentication");
    if (envelope.envelopeId.length !== 16 || envelope.envelopeId.every((byte) => byte === 0)) {
      throw new Error("invalid envelope identity");
    }
    if (request.protocolVersion !== 1) throw new Error("unsupported protocol version");
    if (request.requestId.length !== 16 || request.requestId.every((byte) => byte === 0)) {
      throw new Error("invalid request identity");
    }
    if (authentication.nonce.length !== 16 || authentication.nonce.every((byte) => byte === 0)) {
      throw new Error("invalid authentication nonce");
    }
    if (envelope.responseAuthenticator.length !== 0 || envelope.responseToRequestId.length !== 0) {
      throw new Error("request contains response authentication fields");
    }
    if (authentication.expiresUnixMs <= BigInt(nowUnixMs)) throw new Error("expired authentication");
    if (authentication.keyId.length !== 16 || !timingSafeEqual(this.#keyId, authentication.keyId)) {
      throw new Error("credential identity mismatch");
    }
    const canonical = fromBinary(EnvelopeSchema, toBinary(EnvelopeSchema, envelope));
    const canonicalAuthentication = metadata(canonical)?.authentication;
    if (canonicalAuthentication === undefined) throw new Error("missing authentication");
    canonicalAuthentication.authenticator = new Uint8Array();
    canonicalAuthentication.requestDigest = new Uint8Array();
    const digest = createHash("sha256").update(canonicalRequestBytes(canonical)).digest();
    if (authentication.requestDigest.length !== 32 || !timingSafeEqual(digest, authentication.requestDigest)) {
      throw new Error("request digest mismatch");
    }
    const [participant, launch] = scopes(envelope);
    const hmac = createHmac("sha256", this.#secret).update("navigator.driver.v1\0");
    for (const value of [
      envelope.envelopeId,
      request.requestId,
      authentication.keyId,
      authentication.nonce,
      authentication.requestDigest,
      participant,
      launch,
    ]) lengthPrefixed(hmac, value);
    const protocol = Buffer.alloc(4);
    protocol.writeUInt32BE(request.protocolVersion);
    hmac.update(protocol);
    const expiry = Buffer.alloc(8);
    expiry.writeBigInt64BE(authentication.expiresUnixMs);
    hmac.update(expiry);
    const expected = hmac.digest();
    if (authentication.authenticator.length !== 32 || !timingSafeEqual(expected, authentication.authenticator)) {
      throw new Error("authentication tag mismatch");
    }
    const nonce = `${Buffer.from(authentication.keyId).toString("hex")}:${Buffer.from(authentication.nonce).toString("hex")}`;
    if (this.#nonces.has(nonce)) throw new Error("authentication replay");
    if (this.#nonces.size >= 4096) throw new Error("authentication capacity");
    this.#nonces.set(nonce, authentication.expiresUnixMs);
  }

  signResponse(envelope: Envelope): void {
    envelope.responseAuthenticator = new Uint8Array();
    const digest = createHash("sha256").update(canonicalResponseBytes(envelope)).digest();
    envelope.responseAuthenticator = createHmac("sha256", this.#secret)
      .update("navigator.driver.response.v1\0")
      .update(digest)
      .digest();
  }
}
