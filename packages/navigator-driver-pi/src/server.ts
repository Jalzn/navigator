import { createHash, timingSafeEqual } from "node:crypto";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import {
  Acceptance,
  AcceptanceResponseSchema,
  AcceptanceResultSchema,
  AcceptanceEventSchema,
  CancelDisposition,
  CancelResponseSchema,
  CancelResultSchema,
  CapabilitySchema,
  CapabilityParameterSchema,
  DeliverResponseSchema,
  DeliverResultSchema,
  DeliverRequestSchema,
  DescribeResponseSchema,
  DescribeResultSchema,
  EnvelopeSchema,
  FailureCode,
  FailureSchema,
  DriverEventSchema,
  InspectResponseSchema,
  InspectResultSchema,
  HierarchyCommandSchema,
  HierarchyResultResponseSchema,
  HierarchyResultRequestSchema,
  ToolCommandSchema,
  ToolResultRequestSchema,
  ToolResultResponseSchema,
  SpawnChildCommandSchema,
  SendMessageCommandSchema,
  ParticipantStatusCommandSchema,
  CancelHierarchyCommandSchema,
  InstanceIdentitySchema,
  InstanceState,
  ProtocolRangeSchema,
  ReadySchema,
  ObserveResponseSchema,
  NoEventSchema,
  ReportKind,
  ReportOutcomeSchema,
  ReportSchema,
  RemindDisposition,
  RemindResponseSchema,
  RemindResultSchema,
  StartDisposition,
  StartResponseSchema,
  StartResultSchema,
  StopDisposition,
  StopResponseSchema,
  StopResultSchema,
  type Envelope,
  type InstanceIdentity,
  type DriverEvent,
  type HierarchyCommand,
  type RequestMetadata,
} from "@navigator/driver-protocol/gen/navigator/driver/v1/driver_pb.js";
import { type AcceptedMessage, type InstanceBinding, JournalConflictError, PiAdapter } from "./adapter.js";
import { RequestAuthenticator } from "./auth.js";
import { NavigatorToolBridge, type CancelEmission, type ReportEmission, type SendEmission, type SpawnEmission, type StatusEmission, type ToolEmission, type ToolObservableResult } from "./tools.js";

export type AdapterFactory = (
  binding: InstanceBinding,
  trustedConfiguration: Uint8Array,
  bridge: NavigatorToolBridge,
) => Promise<PiAdapter>;
export type AdvertisedCapability = Readonly<{ id: string; parameters?: Readonly<Record<string, string>> }>;
const MAX_OBSERVE_WAITERS = 64;
const MAX_STOP_LEDGER_ENTRIES = 1024;
const MAX_PENDING_TOOL_COMMANDS = 128;
const HIERARCHY_RESULT_TIMEOUT_MS = 60_000;
export function admitPendingTool(current: number): void {
  if (!Number.isSafeInteger(current) || current < 0 || current >= MAX_PENDING_TOOL_COMMANDS) throw new Error("Tool pending capacity exceeded");
}
const MAX_TOOL_TERMINALS = 1024;
const MAX_TOOL_ARTIFACT_REFS = 32;
const MAX_ARTIFACT_BYTES = 64n * 1024n * 1024n;

export function validateToolSuccess(value: { output: Uint8Array; artifacts: readonly {
  artifactId: Uint8Array; sessionId: Uint8Array; creatorParticipantId: Uint8Array;
  creatorOperationId: Uint8Array; mediaType: string; size: bigint; sha256: Uint8Array;
}[] }): void {
  if (value.output.length === 0 || value.output.length > 65_536) throw new Error("invalid Tool output");
  let decoded: unknown;
  try { decoded = JSON.parse(new TextDecoder().decode(value.output)); } catch { throw new Error("invalid Tool output"); }
  if (JSON.stringify(decoded) !== new TextDecoder().decode(value.output)) throw new Error("invalid Tool output");
  if (value.artifacts.length > MAX_TOOL_ARTIFACT_REFS) throw new Error("too many Tool artifacts");
  for (const artifact of value.artifacts) {
    id(artifact.artifactId, "tool.artifact_id"); id(artifact.sessionId, "tool.session_id");
    id(artifact.creatorParticipantId, "tool.creator_participant_id");
    id(artifact.creatorOperationId, "tool.creator_operation_id");
    if (artifact.mediaType.length === 0 || Buffer.byteLength(artifact.mediaType) > 255) throw new Error("invalid Tool artifact media type");
    if (artifact.size < 0n || artifact.size > MAX_ARTIFACT_BYTES) throw new Error("invalid Tool artifact size");
    if (artifact.sha256.length !== 32) throw new Error("invalid Tool artifact digest");
  }
}

class DispatchFailure extends Error {
  constructor(readonly code: FailureCode, readonly publicMessage: string) {
    super(publicMessage);
  }
}

function conflict(): DispatchFailure {
  return new DispatchFailure(FailureCode.CONFLICT, "request conflicts with driver state");
}

function id(value: Uint8Array, field: string): void {
  if (value.length !== 16 || value.every((byte) => byte === 0)) throw new Error(`invalid ${field}`);
}

function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

function same(left: Uint8Array, right: Uint8Array): boolean {
  return Buffer.from(left).equals(right);
}

function failureEnvelope(request: Envelope, error: unknown): Envelope {
  const classified = error instanceof DispatchFailure || error instanceof JournalConflictError
    ? (error instanceof DispatchFailure ? error : conflict())
    : new DispatchFailure(FailureCode.INTERNAL, "internal driver failure");
  const failure = create(FailureSchema, { code: classified.code, message: classified.publicMessage, retryable: false });
  const inReplyTo = request.envelopeId;
  const result = { case: "failure" as const, value: failure };
  switch (request.body.case) {
    case "describeRequest": return create(EnvelopeSchema, { body: { case: "describeResponse", value: create(DescribeResponseSchema, { inReplyTo, result }) } });
    case "startRequest": return create(EnvelopeSchema, { body: { case: "startResponse", value: create(StartResponseSchema, { inReplyTo, result }) } });
    case "inspectRequest": return create(EnvelopeSchema, { body: { case: "inspectResponse", value: create(InspectResponseSchema, { inReplyTo, result }) } });
    case "deliverRequest": return create(EnvelopeSchema, { body: { case: "deliverResponse", value: create(DeliverResponseSchema, { inReplyTo, result }) } });
    case "acceptanceRequest": return create(EnvelopeSchema, { body: { case: "acceptanceResponse", value: create(AcceptanceResponseSchema, { inReplyTo, result }) } });
    case "cancelRequest": return create(EnvelopeSchema, { body: { case: "cancelResponse", value: create(CancelResponseSchema, { inReplyTo, result }) } });
    case "stopRequest": return create(EnvelopeSchema, { body: { case: "stopResponse", value: create(StopResponseSchema, { inReplyTo, result }) } });
    case "remindRequest": return create(EnvelopeSchema, { body: { case: "remindResponse", value: create(RemindResponseSchema, { inReplyTo, result }) } });
    default: throw error;
  }
}

function metadata(envelope: Envelope): RequestMetadata {
  const direct = ["describeRequest", "inspectRequest", "acceptanceRequest", "observeRequest"];
  if (direct.includes(envelope.body.case ?? "")) {
    const value = envelope.body.value as { metadata?: RequestMetadata };
    if (value.metadata !== undefined) return value.metadata;
  }
  const value = envelope.body.value as { metadata?: { request?: RequestMetadata } };
  if (value.metadata?.request !== undefined) return value.metadata.request;
  throw new Error("missing request metadata");
}

function derivedId(domain: string, input: Uint8Array): Uint8Array {
  const value = createHash("sha256").update(domain).update(input).digest().subarray(0, 16);
  value[6] = (value[6]! & 0x0f) | 0x40;
  value[8] = (value[8]! & 0x3f) | 0x80;
  return value;
}

export function trustedToolCatalog(configuration: Uint8Array): import("./tools.js").TrustedToolCatalogEntry[] {
  let decoded: unknown;
  try { decoded = JSON.parse(new TextDecoder().decode(configuration)); } catch { throw new Error("invalid trusted configuration"); }
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) throw new Error("invalid trusted configuration");
  if (!Object.prototype.hasOwnProperty.call(decoded, "navigator_tool_catalog")) throw new Error("missing trusted Tool catalog");
  const raw = (decoded as { navigator_tool_catalog: unknown }).navigator_tool_catalog;
  if (!Array.isArray(raw) || raw.length > 64) throw new Error("invalid trusted Tool catalog");
  const seen = new Set<string>();
  const seenNames = new Set<string>();
  const reservedNames = new Set([
    "navigator_command", "navigator_report", "navigator_spawn_child",
    "navigator_send_message", "navigator_status_child", "navigator_cancel_child",
  ]);
  const validateSchema = (schema: unknown, depth = 0): schema is Record<string, unknown> => {
    if (depth > 32 || typeof schema !== "object" || schema === null || Array.isArray(schema)) return false;
    const value = schema as Record<string, unknown>;
    const keys = Object.keys(value);
    if (keys.length === 0) return true;
    if (keys.some((key) => !["type", "required", "properties", "items", "additionalProperties"].includes(key))) return false;
    if (!["object", "array", "string", "integer", "number", "boolean", "null"].includes(value.type as string)) return false;
    if (value.required !== undefined && (!Array.isArray(value.required) || value.required.some((item) => typeof item !== "string"))) return false;
    if (value.properties !== undefined) {
      if (typeof value.properties !== "object" || value.properties === null || Array.isArray(value.properties)) return false;
      if (Object.values(value.properties).some((child) => !validateSchema(child, depth + 1))) return false;
    }
    if (value.items !== undefined && !validateSchema(value.items, depth + 1)) return false;
    return value.additionalProperties === undefined || typeof value.additionalProperties === "boolean";
  };
  return raw.map((item) => {
    if (typeof item !== "object" || item === null) throw new Error("invalid trusted Tool entry");
    const value = item as Record<string, unknown>;
    if (Object.keys(value).sort().join(",") !== "input_schema,name,registration_id,version") throw new Error("invalid trusted Tool entry shape");
    if (typeof value.registration_id !== "string" || !/^[0-9a-fA-F]{32}$/.test(value.registration_id)) throw new Error("invalid Tool registration");
    if (/^0{32}$/.test(value.registration_id)) throw new Error("invalid Tool registration");
    if (typeof value.name !== "string" || !/^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/.test(value.name) || Buffer.byteLength(value.name) > 128) throw new Error("invalid Tool name");
    if (typeof value.version !== "string" || !/^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/.test(value.version) || Buffer.byteLength(value.version) > 64) throw new Error("invalid Tool version");
    if (!validateSchema(value.input_schema)) throw new Error("invalid Tool schema");
    const key = value.registration_id.toLowerCase();
    if (seen.has(key)) throw new Error("duplicate Tool registration"); seen.add(key);
    if (reservedNames.has(value.name)) throw new Error("Tool name collides with Navigator built-in");
    if (seenNames.has(value.name)) throw new Error("duplicate Tool name"); seenNames.add(value.name);
    return { registrationId: Buffer.from(key, "hex"), name: value.name, version: value.version, inputSchema: value.input_schema as Record<string, unknown> };
  });
}

export class PiDriverServer {
  readonly #authenticator: RequestAuthenticator;
  readonly #driverId: Uint8Array;
  readonly #factory: AdapterFactory;
  readonly #capabilities: AdvertisedCapability[];
  readonly #capabilityProfileDigest: string;
  #adapter?: PiAdapter;
  #instance?: InstanceIdentity;
  #stopped = false;
  #sequence = 0n;
  readonly #events: DriverEvent[] = [];
  readonly #hierarchyCommands = new Map<string, string>();
  readonly #toolCommands = new Map<string, string>();
  readonly #toolTerminals = new Map<string, string>();
  readonly #stopLedger = new Map<string, { request: Uint8Array; response: Uint8Array }>();
  #cancelState: { operationId: string; completion: Promise<void> } | undefined;
  readonly #bridge: NavigatorToolBridge;
  #startTail: Promise<void> = Promise.resolve();
  #lastDelivery?: import("./tools.js").DeliveryContext;
  #recoveryRequired = false;
  readonly #hierarchyWaiters = new Map<string, { resolve: (value: string) => void; reject: (error: Error) => void }>();
  readonly #toolWaiters = new Map<string, { resolve: (value: ToolObservableResult) => void; reject: (error: Error) => void }>();
  readonly #observeWaiters = new Set<{
    afterSequence: bigint;
    resolve: (event: DriverEvent | undefined) => void;
    reject: (error: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }>();

  constructor(secret: Uint8Array, driverId: Uint8Array, factory: AdapterFactory, capabilities: Array<string | AdvertisedCapability> = []) {
    id(driverId, "driver_id");
    this.#authenticator = new RequestAuthenticator(secret);
    this.#driverId = driverId;
    this.#factory = factory;
    this.#capabilities = capabilities.map((value) => typeof value === "string" ? { id: value } : value);
    this.#capabilityProfileDigest = createHash("sha256").update(JSON.stringify(this.#capabilities.map((capability) => ({
      id: capability.id,
      parameters: Object.entries(capability.parameters ?? {}).sort(([left], [right]) => left.localeCompare(right)),
    })).sort((left, right) => left.id.localeCompare(right.id)))).digest("hex");
    this.#bridge = new NavigatorToolBridge(
      async (report) => this.#publishReport(report),
      async (command) => this.#publishSpawn(command),
      async (command) => this.#publishSend(command),
      async (command) => this.#publishStatus(command),
      async (command) => this.#publishCancel(command),
      async (command) => this.#publishTool(command),
    );
  }

  async stop(): Promise<void> {
    if (this.#stopped) return;
    this.#stopped = true;
    for (const waiter of this.#observeWaiters) {
      clearTimeout(waiter.timer);
      waiter.reject(new Error("instance stopped"));
    }
    this.#observeWaiters.clear();
    for (const waiter of this.#hierarchyWaiters.values()) waiter.reject(new Error("instance stopped"));
    this.#hierarchyWaiters.clear();
    if (this.#adapter !== undefined) await this.#adapter.stop();
  }

  async interactiveLine(line: string): Promise<void> {
    if (this.#recoveryRequired) throw new Error("instance requires hierarchy recovery");
    await this.#requireAdapter().interactiveLine(line);
  }

  async handle(frame: Uint8Array): Promise<Uint8Array> {
    const request = fromBinary(EnvelopeSchema, frame);
    id(request.envelopeId, "envelope_id");
    if (request.body.case === "stopRequest") {
      const key = hex(metadata(request).requestId);
      const prior = this.#stopLedger.get(key);
      if (prior !== undefined && prior.request.length === frame.length && timingSafeEqual(prior.request, frame)) {
        return prior.response;
      }
    }
    // Authentication is deliberately outside the dispatch failure boundary. An
    // unauthenticated peer gets no signed response and cannot use this endpoint
    // as either a signing oracle or a stop-ledger occupancy oracle.
    this.#authenticator.verify(request);
    let response: Envelope;
    try {
      const authenticatedStopConflict = request.body.case === "stopRequest"
        && this.#stopLedger.has(hex(metadata(request).requestId));
      if (authenticatedStopConflict) throw conflict();
      response = await this.#dispatch(request);
    } catch (error) {
      response = failureEnvelope(request, error);
    }
    response.responseToRequestId = metadata(request).requestId;
    response.envelopeId = derivedId("navigator.pi.reply\0", request.envelopeId);
    this.#authenticator.signResponse(response);
    const encoded = toBinary(EnvelopeSchema, response);
    if (request.body.case === "stopRequest") {
      const key = hex(metadata(request).requestId);
      if (this.#stopLedger.has(key)) return encoded;
      if (this.#stopLedger.size >= MAX_STOP_LEDGER_ENTRIES) {
        const oldest = this.#stopLedger.keys().next().value as string | undefined;
        if (oldest !== undefined) this.#stopLedger.delete(oldest);
      }
      this.#stopLedger.set(key, { request: Buffer.from(frame), response: encoded });
    }
    return encoded;
  }

  async #dispatch(request: Envelope): Promise<Envelope> {
    switch (request.body.case) {
      case "describeRequest":
        return create(EnvelopeSchema, { body: { case: "describeResponse", value: create(DescribeResponseSchema, {
          inReplyTo: request.envelopeId,
          result: { case: "success", value: create(DescribeResultSchema, {
            driverId: this.#driverId,
            implementation: "navigator-pi",
            implementationVersion: "0.1.0",
            protocol: create(ProtocolRangeSchema, { minimum: 1, maximum: 1 }),
            capabilities: this.#capabilities.map((capability) => create(CapabilitySchema, {
              id: capability.id,
              version: 1,
              parameters: Object.entries(capability.parameters ?? {}).map(([key, value]) => create(CapabilityParameterSchema, { key, value })),
            })),
          }) },
        }) } });
      case "startRequest": {
        const previousStart = this.#startTail;
        let releaseStart!: () => void;
        this.#startTail = new Promise<void>((resolve) => { releaseStart = resolve; });
        await previousStart;
        try {
        const value = request.body.value;
        for (const [field, identity] of [
          ["participant_id", value.participantId],
          ["launch_attempt_id", value.launchAttemptId],
          ["instance_id", value.instanceId],
          ["session_id", value.sessionId],
        ] as const) id(identity, field);
        if (value.ownershipEpoch === 0n) throw new Error("invalid ownership epoch");
        const instance = create(InstanceIdentitySchema, {
          driverId: this.#driverId,
          participantId: value.participantId,
          launchAttemptId: value.launchAttemptId,
          instanceId: value.instanceId,
          sessionId: value.sessionId,
          ownershipEpoch: value.ownershipEpoch,
        });
        const trustedConfigurationDigest = createHash("sha256").update(value.trustedConfiguration).digest("hex");
        if (this.#instance !== undefined) {
          if (!same(
            toBinary(InstanceIdentitySchema, this.#instance),
            toBinary(InstanceIdentitySchema, instance),
          )) {
            throw new Error("start identity conflict");
          }
          const prior = this.#requireAdapter().identity();
          if (prior.trustedConfigurationDigest !== trustedConfigurationDigest
            || prior.capabilityProfileDigest !== this.#capabilityProfileDigest) throw new Error("start semantic conflict");
        } else {
          this.#bridge.configureToolCatalog(trustedToolCatalog(value.trustedConfiguration));
          const binding: InstanceBinding = {
            driverId: hex(this.#driverId),
            sessionId: hex(value.sessionId),
            participantId: hex(value.participantId),
            launchAttemptId: hex(value.launchAttemptId),
            instanceId: hex(value.instanceId),
            ownershipEpoch: value.ownershipEpoch,
            trustedConfigurationDigest,
            capabilityProfileDigest: this.#capabilityProfileDigest,
          };
          const candidate = await this.#factory(binding, value.trustedConfiguration, this.#bridge);
          const recovered: DriverEvent[] = [];
          let acknowledgedHierarchyWithoutTranscriptProof = false;
          try {
            let priorSequence = 0n;
            for (const stored of candidate.persistedEvents()) {
              const event = fromBinary(DriverEventSchema, Buffer.from(stored.payload, "base64"));
              if (event.sequence !== stored.sequence || event.sequence <= priorSequence) throw new Error("event journal sequence mismatch");
              if (event.instance === undefined || !same(toBinary(InstanceIdentitySchema, event.instance), toBinary(InstanceIdentitySchema, instance))) {
                throw new Error("event journal identity mismatch");
              }
              id(event.inReplyTo, "event in_reply_to");
              if (event.event.case === "hierarchyCommand") {
                const key = hex(event.event.value.requestId);
                const commandSemantic = stored.payload;
                const prior = this.#hierarchyCommands.get(key);
                if (prior !== undefined && prior !== commandSemantic) throw new Error("hierarchy request command conflict");
                this.#hierarchyCommands.set(key, commandSemantic);
                if (candidate.hierarchyResult(key, commandSemantic) === undefined) recovered.push(event);
                else acknowledgedHierarchyWithoutTranscriptProof = true;
              } else if (event.event.case === "toolCommand") {
                const key = hex(event.event.value.requestId);
                const prior = this.#toolCommands.get(key);
                if (prior !== undefined && prior !== stored.payload) throw new Error("Tool request command conflict");
                this.#toolCommands.set(key, stored.payload);
                recovered.push(event);
              } else recovered.push(event);
              priorSequence = event.sequence;
            }
          } catch (error) {
            await candidate.stop().catch(() => undefined);
            throw error;
          }
          this.#adapter = candidate;
          this.#instance = instance;
          this.#events.push(...recovered);
          const persisted = candidate.persistedEvents();
          if (persisted.length !== 0) this.#sequence = persisted[persisted.length - 1]!.sequence;
          this.#recoveryRequired = acknowledgedHierarchyWithoutTranscriptProof
            || recovered.some((event) => event.event.case === "hierarchyCommand");
          if (this.#events.length === 0) this.#appendEvent(create(DriverEventSchema, {
            eventId: derivedId("navigator.pi.ready\0", request.envelopeId),
            instance,
            sequence: ++this.#sequence,
            inReplyTo: request.envelopeId,
            event: { case: "ready", value: create(ReadySchema, {
              capabilities: this.#capabilities.map((capability) => create(CapabilitySchema, {
                id: capability.id,
                version: 1,
                parameters: Object.entries(capability.parameters ?? {}).map(([key, value]) => create(CapabilityParameterSchema, { key, value })),
              })),
            }) },
          }));
          for (const delivered of candidate.acceptedMessages()) {
            const messageId = Buffer.from(delivered.messageId, "hex");
            const deliveryAttemptId = Buffer.from(delivered.deliveryAttemptId, "hex");
            const recordedAcceptance = this.#events.find((event) => event.event.case === "acceptance"
              && same(event.event.value.messageId, messageId)
              && same(event.event.value.deliveryAttemptId, deliveryAttemptId));
            const cause = Buffer.from(delivered.causeEnvelopeId, "hex");
            if (recordedAcceptance !== undefined && !same(recordedAcceptance.inReplyTo, cause)) {
              throw new Error("acceptance event cause mismatch");
            }
            if (recordedAcceptance === undefined) this.#appendEvent(create(DriverEventSchema, {
              eventId: derivedId("navigator.pi.acceptance\0", deliveryAttemptId),
              instance,
              sequence: ++this.#sequence,
              event: { case: "acceptance", value: create(AcceptanceEventSchema, {
                messageId, deliveryAttemptId, acceptance: Acceptance.ACCEPTED,
              }) },
              inReplyTo: cause,
            }));
          }
          for (const pending of this.#recoveryRequired ? [] : candidate.pendingMessages()) {
            const canonical = Buffer.from(pending.canonicalPayload, "base64");
            const decoded = fromBinary(DeliverRequestSchema, canonical);
            if (decoded.instance === undefined
              || !same(toBinary(InstanceIdentitySchema, decoded.instance), toBinary(InstanceIdentitySchema, instance))
              || hex(decoded.messageId) !== pending.messageId
              || hex(decoded.deliveryAttemptId) !== pending.deliveryAttemptId
              || (decoded.operationId.length === 0 ? null : hex(decoded.operationId)) !== pending.operationId
              || Buffer.from(toBinary(DeliverRequestSchema, decoded)).toString("base64") !== pending.canonicalPayload) {
              throw new Error("pending delivery journal binding mismatch");
            }
            await candidate.deliver(pending, new TextDecoder("utf-8", { fatal: true }).decode(decoded.payload));
          }
        }
        return create(EnvelopeSchema, { body: { case: "startResponse", value: create(StartResponseSchema, {
          inReplyTo: request.envelopeId,
          result: { case: "success", value: create(StartResultSchema, {
            disposition: StartDisposition.STARTED,
            instance,
          }) },
        }) } });
        } finally {
          releaseStart();
        }
      }
      case "inspectRequest": {
        this.#requireIdentity(request.body.value.instance);
        return create(EnvelopeSchema, { body: { case: "inspectResponse", value: create(InspectResponseSchema, {
          inReplyTo: request.envelopeId,
          result: { case: "success", value: create(InspectResultSchema, {
            state: this.#stopped ? InstanceState.STOPPED
              : this.#recoveryRequired ? InstanceState.INSTANCE_UNCERTAIN : InstanceState.READY,
            lastEventSequence: this.#sequence,
          }) },
        }) } });
      }
      case "deliverRequest": {
        const instance = request.body.value.instance;
        if (instance === undefined) throw new Error("instance identity missing");
        this.#requireIdentity(instance);
        const adapter = this.#requireAdapter();
        if (this.#recoveryRequired) throw new Error("instance requires hierarchy recovery");
        const value = request.body.value;
        id(value.messageId, "message_id");
        id(value.deliveryAttemptId, "delivery_attempt_id");
        const record: AcceptedMessage = {
          messageId: hex(value.messageId),
          deliveryAttemptId: hex(value.deliveryAttemptId),
          operationId: value.operationId.length === 0 ? null : hex(value.operationId),
          canonicalPayload: Buffer.from(toBinary(DeliverRequestSchema, create(DeliverRequestSchema, {
            instance,
            messageId: value.messageId,
            operationId: value.operationId,
            payload: value.payload,
            pendingCorrelations: value.pendingCorrelations,
            deliveryAttemptId: value.deliveryAttemptId,
          }))).toString("base64"),
          causeEnvelopeId: hex(request.envelopeId),
        };
        await adapter.deliver(record, new TextDecoder("utf-8", { fatal: true }).decode(value.payload));
        const durableContext = adapter.deliveryContext();
        if (durableContext !== undefined) this.#lastDelivery = durableContext;
        const acceptanceRecorded = this.#events.some((event) => event.event.case === "acceptance"
          && same(event.event.value.messageId, value.messageId)
          && same(event.event.value.deliveryAttemptId, value.deliveryAttemptId));
        if (!acceptanceRecorded) this.#appendEvent(create(DriverEventSchema, {
          eventId: derivedId("navigator.pi.acceptance\0", value.deliveryAttemptId),
          instance,
          sequence: ++this.#sequence,
          event: { case: "acceptance", value: create(AcceptanceEventSchema, {
            messageId: value.messageId,
            deliveryAttemptId: value.deliveryAttemptId,
            acceptance: Acceptance.ACCEPTED,
          }) },
          inReplyTo: request.envelopeId,
        }));
        return create(EnvelopeSchema, { body: { case: "deliverResponse", value: create(DeliverResponseSchema, {
          inReplyTo: request.envelopeId,
          result: { case: "success", value: create(DeliverResultSchema, {
            acceptance: Acceptance.ACCEPTED,
            messageId: value.messageId,
            deliveryAttemptId: value.deliveryAttemptId,
          }) },
        }) } });
      }
      case "acceptanceRequest": {
        this.#requireIdentity(request.body.value.instance);
        const value = request.body.value;
        const acceptance = this.#requireAdapter().acceptance(hex(value.messageId), hex(value.deliveryAttemptId));
        const mapped = acceptance === "accepted" ? Acceptance.ACCEPTED
          : acceptance === "not_accepted" ? Acceptance.NOT_ACCEPTED : Acceptance.ACCEPTANCE_UNKNOWN;
        return create(EnvelopeSchema, { body: { case: "acceptanceResponse", value: create(AcceptanceResponseSchema, {
          inReplyTo: request.envelopeId,
          result: { case: "success", value: create(AcceptanceResultSchema, {
            acceptance: mapped,
            deliveryAttemptId: value.deliveryAttemptId,
          }) },
        }) } });
      }
      case "cancelRequest":
        this.#requireIdentity(request.body.value.instance);
        id(request.body.value.operationId, "operation_id");
        const cancelledOperation = hex(request.body.value.operationId);
        if (!this.#requireAdapter().hasAcceptedOperation(cancelledOperation)) throw new Error("operation identity mismatch");
        if (this.#cancelState?.operationId !== cancelledOperation) {
          this.#cancelState = { operationId: cancelledOperation, completion: this.#requireAdapter().cancel() };
        }
        const cancelState = this.#cancelState;
        try { await cancelState.completion; }
        catch (error) { if (this.#cancelState === cancelState) this.#cancelState = undefined; throw error; }
        return create(EnvelopeSchema, { body: { case: "cancelResponse", value: create(CancelResponseSchema, {
          inReplyTo: request.envelopeId,
          result: { case: "success", value: create(CancelResultSchema, {
            disposition: CancelDisposition.CANCEL_REQUESTED,
          }) },
        }) } });
      case "stopRequest":
        this.#requireIdentity(request.body.value.instance);
        const alreadyStopped = this.#stopped;
        await this.stop();
        return create(EnvelopeSchema, { body: { case: "stopResponse", value: create(StopResponseSchema, {
          inReplyTo: request.envelopeId,
          result: { case: "success", value: create(StopResultSchema, {
            disposition: alreadyStopped ? StopDisposition.ALREADY_STOPPED : StopDisposition.STOPPED_CONFIRMED,
          }) },
        }) } });
      case "observeRequest": {
        const value = request.body.value;
        this.#requireIdentity(value.instance);
        const event = this.#events.find((candidate) => candidate.sequence > value.afterSequence)
          ?? await this.#waitForEvent(value.afterSequence);
        if (event === undefined) return create(EnvelopeSchema, { body: { case: "observeResponse", value: create(ObserveResponseSchema, {
          inReplyTo: request.envelopeId, result: { case: "noEvent", value: create(NoEventSchema) },
        }) } });
        if (event.instance === undefined) throw new Error("event identity missing");
        return create(EnvelopeSchema, {
          body: { case: "observeResponse", value: create(ObserveResponseSchema, { inReplyTo: request.envelopeId, result: { case: "event", value: create(DriverEventSchema, {
            eventId: event.eventId,
            instance: event.instance,
            sequence: event.sequence,
            event: event.event,
            inReplyTo: event.inReplyTo,
          }) } }) },
        });
      }
      case "remindRequest": {
        const value = request.body.value;
        this.#requireIdentity(value.instance);
        id(value.operationId, "operation_id");
        id(value.messageId, "message_id");
        const context = this.#requireKnownDelivery();
        if (!same(value.operationId, context.operationId) || !same(value.messageId, context.messageId)) throw new Error("delivery identity mismatch");
        await this.#requireAdapter().remind();
        return create(EnvelopeSchema, {
          body: { case: "remindResponse", value: create(RemindResponseSchema, {
            inReplyTo: request.envelopeId,
            result: { case: "success", value: create(RemindResultSchema, {
              disposition: RemindDisposition.REMINDER_REQUESTED,
            }) },
          }) },
        });
      }
      case "hierarchyResultRequest": {
        const value = request.body.value;
        this.#requireIdentity(value.instance);
        id(value.hierarchyRequestId, "hierarchy_request_id");
        const key = hex(value.hierarchyRequestId);
        const commandSemantic = this.#hierarchyCommands.get(key);
        if (commandSemantic === undefined) throw new Error("unknown hierarchy request");
        if (value.result.case === undefined) throw new Error("missing hierarchy result");
        const semanticValue = create(HierarchyResultRequestSchema, {
          ...(value.instance === undefined ? {} : { instance: value.instance }),
          hierarchyRequestId: value.hierarchyRequestId,
          result: value.result,
        });
        const semantic = Buffer.from(toBinary(HierarchyResultRequestSchema, semanticValue)).toString("base64");
        const disposition = this.#requireAdapter().recordHierarchyResult(key, commandSemantic, semantic);
        const waiter = this.#hierarchyWaiters.get(key);
        if (waiter !== undefined) this.#hierarchyWaiters.delete(key);
        if (waiter !== undefined && value.result.case === "failure") {
          waiter.reject(new Error("Navigator rejected hierarchy command"));
        } else if (waiter !== undefined) {
          waiter.resolve(`Navigator hierarchy ${value.result.case} committed for request ${key}.`);
        }
        void disposition;
        return create(EnvelopeSchema, {
          body: { case: "hierarchyResultResponse", value: create(HierarchyResultResponseSchema, {
            inReplyTo: request.envelopeId,
            hierarchyRequestId: value.hierarchyRequestId,
          }) },
        });
      }
      case "toolResultRequest": {
        const value = request.body.value;
        this.#requireIdentity(value.instance);
        id(value.toolRequestId, "tool_request_id");
        if (value.result.case === undefined) throw new Error("missing tool result");
        if (value.result.case === "success") validateToolSuccess(value.result.value);
        const key = hex(value.toolRequestId);
        const semanticValue = create(ToolResultRequestSchema, {
          ...(value.instance === undefined ? {} : { instance: value.instance }),
          toolRequestId: value.toolRequestId, result: value.result,
        });
        const semantic = Buffer.from(toBinary(ToolResultRequestSchema, semanticValue)).toString("base64");
        const terminal = this.#toolTerminals.get(key);
        if (terminal !== undefined && terminal !== semantic) throw new Error("Tool terminal conflict");
        if (terminal === undefined && !this.#toolCommands.has(key)) throw new Error("unknown tool request");
        if (terminal === undefined) {
          if (this.#toolTerminals.size >= MAX_TOOL_TERMINALS) this.#toolTerminals.delete(this.#toolTerminals.keys().next().value!);
          this.#toolTerminals.set(key, semantic);
        }
        const waiter = this.#toolWaiters.get(key);
        if (waiter !== undefined) this.#toolWaiters.delete(key);
        this.#toolCommands.delete(key);
        if (terminal === undefined && value.result.case === "success") waiter?.resolve({
          outputBase64: Buffer.from(value.result.value.output).toString("base64"),
          artifacts: value.result.value.artifacts.map((artifact) => ({
            artifactId: hex(artifact.artifactId), sessionId: hex(artifact.sessionId),
            creatorParticipantId: hex(artifact.creatorParticipantId), creatorOperationId: hex(artifact.creatorOperationId),
            mediaType: artifact.mediaType, size: artifact.size.toString(), sha256: Buffer.from(artifact.sha256).toString("hex"),
          })),
        });
        if (terminal === undefined && value.result.case === "failure") waiter?.reject(new Error(value.result.value.message));
        return create(EnvelopeSchema, { body: { case: "toolResultResponse", value: create(ToolResultResponseSchema, {
          inReplyTo: request.envelopeId, toolRequestId: value.toolRequestId,
        }) } });
      }
      default:
        throw new Error(`unsupported request: ${request.body.case ?? "missing"}`);
    }
  }

  #requireAdapter(): PiAdapter {
    if (this.#adapter === undefined) throw new Error("instance not started");
    return this.#adapter;
  }

  async #publishReport(report: ReportEmission): Promise<void> {
    if (this.#instance === undefined) {
      throw new Error("report has no active delivery identity");
    }
    const context = this.#requireDeliveryContext();
    const kinds: Record<ReportEmission["kind"], ReportKind> = {
      progress: ReportKind.PROGRESS,
      question: ReportKind.QUESTION,
      blocked: ReportKind.BLOCKED,
      succeeded: ReportKind.SUCCEEDED,
      failed: ReportKind.REPORT_FAILED,
      cancelled: ReportKind.REPORT_CANCELLED,
      uncertain: ReportKind.REPORT_UNCERTAIN,
    };
    if (["succeeded", "failed", "cancelled", "uncertain"].includes(report.kind)) {
      const replay = this.#events.some((event) => event.event.case === "report"
        && same(event.event.value.operationId, context.operationId)
        && same(event.event.value.messageId, context.messageId)
        && same(event.event.value.deliveryAttemptId, context.deliveryAttemptId)
        && event.event.value.result.case === "outcome"
        && event.event.value.result.value.kind === kinds[report.kind]
        && same(event.event.value.result.value.payload, report.payload));
      if (replay) return;
    }
    const sequence = ++this.#sequence;
    this.#appendEvent(create(DriverEventSchema, {
      eventId: derivedId("navigator.pi.report\0", Buffer.concat([
        Buffer.from(context.operationId),
        Buffer.from(sequence.toString()),
      ])),
      instance: this.#instance,
      sequence,
      event: { case: "report", value: create(ReportSchema, {
        operationId: context.operationId,
        messageId: context.messageId,
        deliveryAttemptId: context.deliveryAttemptId,
        result: { case: "outcome", value: create(ReportOutcomeSchema, {
          kind: kinds[report.kind],
          payload: report.payload,
        }) },
      }) },
      inReplyTo: context.inReplyTo,
    }));
  }

  async #publishSpawn(command: SpawnEmission): Promise<string> {
    if (this.#instance === undefined) throw new Error("hierarchy command has no instance identity");
    id(command.requestId, "hierarchy.request_id");
    id(command.templateId, "hierarchy.template_id");
    if (command.grantId.length !== 0) id(command.grantId, "hierarchy.grant_id");
    const key = hex(command.requestId);
    if (this.#hierarchyWaiters.has(key)) throw new Error("hierarchy request already pending");
    const result = this.#waitForHierarchy(key);
    this.#appendEvent(create(DriverEventSchema, {
      eventId: derivedId("navigator.pi.hierarchy\0", command.requestId),
      instance: this.#instance,
      sequence: ++this.#sequence,
      event: { case: "hierarchyCommand", value: create(HierarchyCommandSchema, {
        requestId: command.requestId,
        command: { case: "spawnChild", value: create(SpawnChildCommandSchema, {
          templateId: command.templateId,
          taskInput: command.taskInput,
          grantId: command.grantId,
        }) },
      }) },
      inReplyTo: this.#requireDeliveryContext().inReplyTo,
    }));
    return result;
  }

  #publishHierarchy(
    requestId: Uint8Array,
    command: HierarchyCommand["command"],
  ): Promise<string> {
    if (this.#instance === undefined) throw new Error("hierarchy command has no instance identity");
    id(requestId, "hierarchy.request_id");
    const key = hex(requestId);
    if (this.#hierarchyWaiters.has(key)) throw new Error("hierarchy request already pending");
    const result = this.#waitForHierarchy(key);
    this.#appendEvent(create(DriverEventSchema, {
      eventId: derivedId("navigator.pi.hierarchy\0", requestId), instance: this.#instance,
      sequence: ++this.#sequence,
      event: { case: "hierarchyCommand", value: create(HierarchyCommandSchema, { requestId, command }) },
      inReplyTo: this.#requireDeliveryContext().inReplyTo,
    }));
    return result;
  }

  #publishSend(command: SendEmission): Promise<string> {
    id(command.destinationId, "hierarchy.destination_participant_id");
    return this.#publishHierarchy(command.requestId, { case: "send", value: create(SendMessageCommandSchema, {
      destinationParticipantId: command.destinationId, validatedEnvelope: command.envelope,
    }) });
  }

  #publishStatus(command: StatusEmission): Promise<string> {
    id(command.participantId, "hierarchy.participant_id"); id(command.operationId, "hierarchy.operation_id");
    return this.#publishHierarchy(command.requestId, { case: "status", value: create(ParticipantStatusCommandSchema, {
      participantId: command.participantId, operationId: command.operationId,
    }) });
  }

  #publishCancel(command: CancelEmission): Promise<string> {
    id(command.participantId, "hierarchy.participant_id"); id(command.operationId, "hierarchy.operation_id");
    return this.#publishHierarchy(command.requestId, { case: "cancel", value: create(CancelHierarchyCommandSchema, {
      participantId: command.participantId, operationId: command.operationId,
    }) });
  }

  #publishTool(command: ToolEmission): Promise<ToolObservableResult> {
    if (this.#instance === undefined) throw new Error("tool command has no instance identity");
    id(command.requestId, "tool.request_id");
    if (!/^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/.test(command.name) || Buffer.byteLength(command.name) > 128) throw new Error("invalid tool name");
    if (!/^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/.test(command.version) || Buffer.byteLength(command.version) > 64) throw new Error("invalid tool version");
    if (command.input.length > 65536) throw new Error("tool input exceeds bound");
    if (command.grantId.length !== 0) id(command.grantId, "tool.grant_id");
    const context = this.#requireDeliveryContext();
    const key = hex(command.requestId);
    admitPendingTool(this.#toolCommands.size);
    if (this.#toolWaiters.has(key) || this.#toolCommands.has(key)) throw new Error("tool request already pending");
    const result = new Promise<ToolObservableResult>((resolve, reject) => this.#toolWaiters.set(key, { resolve, reject }));
    const event = create(DriverEventSchema, {
      eventId: derivedId("navigator.pi.tool\0", command.requestId), instance: this.#instance,
      sequence: ++this.#sequence,
      event: { case: "toolCommand", value: create(ToolCommandSchema, {
        requestId: command.requestId, sessionId: this.#instance.sessionId,
        participantId: this.#instance.participantId, operationId: context.operationId,
        toolName: command.name, toolVersion: command.version, input: command.input,
        authorityGrantId: command.grantId,
      }) },
      inReplyTo: context.inReplyTo,
    });
    this.#toolCommands.set(key, Buffer.from(toBinary(DriverEventSchema, event)).toString("base64"));
    this.#appendEvent(event);
    return result;
  }

  #requireIdentity(value: InstanceIdentity | undefined): void {
    if (value === undefined || this.#instance === undefined) throw conflict();
    const identities: Array<[Uint8Array, Uint8Array]> = [
      [value.driverId, this.#instance.driverId],
      [value.sessionId, this.#instance.sessionId],
      [value.participantId, this.#instance.participantId],
      [value.launchAttemptId, this.#instance.launchAttemptId],
      [value.instanceId, this.#instance.instanceId],
    ];
    for (const [left, right] of identities) if (!same(left, right)) throw conflict();
    if (value.ownershipEpoch !== this.#instance.ownershipEpoch) throw conflict();
  }

  #requireDeliveryContext(): import("./tools.js").DeliveryContext {
    const context = this.#bridge.context();
    if (context === undefined) throw new Error("no active Navigator delivery");
    return context;
  }

  #requireKnownDelivery(): import("./tools.js").DeliveryContext {
    return this.#bridge.context() ?? this.#lastDelivery ?? (() => { throw new Error("no known Navigator delivery"); })();
  }

  #appendEvent(event: DriverEvent): void {
    id(event.inReplyTo, "event in_reply_to");
    const semantic = Buffer.from(toBinary(DriverEventSchema, event)).toString("base64");
    if (event.event.case === "hierarchyCommand") {
      const key = hex(event.event.value.requestId);
      const prior = this.#hierarchyCommands.get(key);
      if (prior !== undefined && prior !== semantic) throw new Error("hierarchy request command conflict");
      if (prior !== undefined) throw new Error("hierarchy request already published");
      this.#hierarchyCommands.set(key, semantic);
    }
    this.#requireAdapter().appendEvent(event.sequence, semantic);
    this.#events.push(event);
    for (const waiter of [...this.#observeWaiters]) {
      if (event.sequence <= waiter.afterSequence) continue;
      this.#observeWaiters.delete(waiter);
      clearTimeout(waiter.timer);
      waiter.resolve(event);
    }
  }

  #waitForEvent(afterSequence: bigint): Promise<DriverEvent | undefined> {
    if (this.#stopped) return Promise.reject(new Error("instance stopped"));
    if (this.#observeWaiters.size >= MAX_OBSERVE_WAITERS) {
      return Promise.reject(new Error("observe waiter capacity exceeded"));
    }
    return new Promise<DriverEvent | undefined>((resolve, reject) => {
      const waiter = { afterSequence, resolve, reject, timer: undefined as unknown as ReturnType<typeof setTimeout> };
      waiter.timer = setTimeout(() => {
        if (this.#observeWaiters.delete(waiter)) resolve(undefined);
      }, 100);
      this.#observeWaiters.add(waiter);
      // Registration and the preceding lookup share one JS turn, so append
      // cannot occur between them. This second lookup also keeps the helper
      // correct if it is later called from a context that can yield.
      const ready = this.#events.find((candidate) => candidate.sequence > afterSequence);
      if (ready !== undefined && this.#observeWaiters.delete(waiter)) resolve(ready);
    });
  }

  #waitForHierarchy(key: string): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.#hierarchyWaiters.delete(key)) reject(new Error("hierarchy result timeout"));
      }, HIERARCHY_RESULT_TIMEOUT_MS);
      this.#hierarchyWaiters.set(key, {
        resolve: (value) => { clearTimeout(timer); resolve(value); },
        reject: (error) => { clearTimeout(timer); reject(error); },
      });
    });
  }
}
