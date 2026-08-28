import { closeSync, constants, fstatSync, fsyncSync, ftruncateSync, lstatSync, mkdirSync, openSync, readFileSync, readSync, renameSync, rmSync, writeFileSync, writeSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { fromBinary, toBinary } from "@bufbuild/protobuf";
import { DriverEventSchema, HierarchyResultRequestSchema } from "@navigator/driver-protocol/gen/navigator/driver/v1/driver_pb.js";
import type { NavigatorToolBridge } from "./tools.js";
import type { JournalFaultController, JournalFaultTarget } from "./journal-fault.js";

export const MAX_FRAME_BYTES = 1024 * 1024;
export const MAX_PENDING_DELIVERIES = 64;
export const MAX_JOURNAL_BYTES = 16 * 1024 * 1024;
export const MAX_JOURNAL_RECORDS = 100_000;

/** A valid request conflicts with semantic state already committed by the journal. */
export class JournalConflictError extends Error {}

export type InstanceBinding = Readonly<{
  driverId: string;
  sessionId: string;
  participantId: string;
  launchAttemptId: string;
  instanceId: string;
  ownershipEpoch: bigint;
  trustedConfigurationDigest?: string;
  capabilityProfileDigest?: string;
}>;

export interface PiSession {
  prompt(text: string): Promise<void>;
  steer(text: string): Promise<void>;
  abort(): Promise<void>;
  dispose(): void | Promise<void>;
  subscribe(listener: (event: unknown) => void): () => void;
  lastAssistantText(): string;
}

export type AcceptedMessage = Readonly<{
  messageId: string;
  deliveryAttemptId: string;
  operationId: string | null;
  canonicalPayload: string;
  causeEnvelopeId: string;
}>;

type JournalRecord =
  | Readonly<{ version: 3; kind: "binding"; binding: InstanceBinding }>
  | Readonly<{ version: 3; kind: "pending"; binding: InstanceBinding; message: AcceptedMessage }>
  | Readonly<{ version: 3; kind: "delivered"; binding: InstanceBinding; messageId: string }>
  | Readonly<{ version: 3; kind: "event"; binding: InstanceBinding; sequence: string; payload: string }>
  | Readonly<{ version: 3; kind: "hierarchy_result"; binding: InstanceBinding; requestId: string; commandSemantic: string; resultSemantic: string }>;

type JournalFaultHook = (point: "before_fsync" | "after_fsync") => void;

function appendDurably(path: string, value: JournalRecord, fault?: JournalFaultHook, controller?: JournalFaultController, target?: JournalFaultTarget): void {
  const line = `${JSON.stringify(
    value,
    (_key, item: unknown) => typeof item === "bigint" ? `${item}n` : item,
  )}\n`;
  const descriptor = openSync(path, "a", 0o600);
  try {
    if (fstatSync(descriptor).size + Buffer.byteLength(line) > MAX_JOURNAL_BYTES) {
      throw new Error("acceptance journal capacity exceeded");
    }
    if (target !== undefined) controller?.reach("before_append", target);
    const encoded = Buffer.from(line);
    let offset = 0;
    while (offset < encoded.length) {
      const written = writeSync(descriptor, encoded, offset, encoded.length - offset);
      if (written <= 0) throw new Error("acceptance journal write made no progress");
      offset += written;
    }
    fault?.("before_fsync");
    fsyncSync(descriptor);
    if (target !== undefined) controller?.reach("after_fsync", target);
    fault?.("after_fsync");
  } finally {
    closeSync(descriptor);
  }
}

function stableBinding(left: InstanceBinding, right: InstanceBinding): boolean {
  return left.driverId === right.driverId
    && left.sessionId === right.sessionId
    && left.participantId === right.participantId
    && left.launchAttemptId === right.launchAttemptId
    && left.instanceId === right.instanceId
    && left.ownershipEpoch === right.ownershipEpoch
    && left.trustedConfigurationDigest === right.trustedConfigurationDigest
    && left.capabilityProfileDigest === right.capabilityProfileDigest;
}

function exactHex(value: unknown, bytes: number): value is string {
  return typeof value === "string" && new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(value);
}

function canonicalBase64(value: string): Buffer {
  const decoded = Buffer.from(value, "base64");
  if (decoded.length === 0 || decoded.toString("base64") !== value) throw new Error("invalid hierarchy semantic encoding");
  return decoded;
}

function validateHierarchyResultSemantic(binding: InstanceBinding, requestId: string, semantic: string): void {
  let result;
  try { result = fromBinary(HierarchyResultRequestSchema, canonicalBase64(semantic)); }
  catch { throw new Error("invalid hierarchy result semantic"); }
  if (Buffer.from(toBinary(HierarchyResultRequestSchema, result)).toString("base64") !== semantic
    || Buffer.from(result.hierarchyRequestId).toString("hex") !== requestId
    || result.result.case === undefined || result.instance === undefined
    || Buffer.from(result.instance.driverId).toString("hex") !== binding.driverId
    || Buffer.from(result.instance.sessionId).toString("hex") !== binding.sessionId
    || Buffer.from(result.instance.participantId).toString("hex") !== binding.participantId
    || Buffer.from(result.instance.launchAttemptId).toString("hex") !== binding.launchAttemptId
    || Buffer.from(result.instance.instanceId).toString("hex") !== binding.instanceId
    || result.instance.ownershipEpoch !== binding.ownershipEpoch) throw new Error("invalid hierarchy result semantic");
}

function validateHierarchyCommandSemantic(events: ReadonlyArray<{ payload: string }>, requestId: string, semantic: string): void {
  if (!events.some((event) => event.payload === semantic)) throw new Error("hierarchy result lacks prior command event");
  let event;
  try { event = fromBinary(DriverEventSchema, canonicalBase64(semantic)); }
  catch { throw new Error("invalid hierarchy command semantic"); }
  if (event.event.case !== "hierarchyCommand"
    || Buffer.from(event.event.value.requestId).toString("hex") !== requestId) throw new Error("invalid hierarchy command semantic");
}

function validateBinding(value: unknown): value is InstanceBinding {
  if (typeof value !== "object" || value === null) return false;
  const item = value as Record<string, unknown>;
  return exactHex(item.driverId, 16) && exactHex(item.sessionId, 16)
    && exactHex(item.participantId, 16) && exactHex(item.launchAttemptId, 16)
    && exactHex(item.instanceId, 16) && typeof item.ownershipEpoch === "bigint"
    && (item.trustedConfigurationDigest === undefined || exactHex(item.trustedConfigurationDigest, 32))
    && (item.capabilityProfileDigest === undefined || exactHex(item.capabilityProfileDigest, 32));
}

function processStartToken(pid: number): string | null {
  const result = spawnSync("ps", ["-o", "lstart=", "-p", String(pid)], { encoding: "utf8" });
  if (result.status !== 0) return null;
  const value = result.stdout.trim();
  return value.length === 0 ? null : value;
}

function acquireProcessLock(path: string): string {
  const token = processStartToken(process.pid);
  if (token === null) throw new Error("cannot establish process identity for journal lock");
  const nonce = randomBytes(16).toString("hex");
  try {
    mkdirSync(path, { mode: 0o700 });
    writeFileSync(`${path}/owner`, JSON.stringify({ version: 1, pid: process.pid, start: token, nonce }), { mode: 0o600, flag: "wx" });
    const directory = openSync(path, "r"); try { fsyncSync(directory); } finally { closeSync(directory); }
    return nonce;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) {
    throw new Error("unsafe journal lock identity");
  }
  const claim = openSync(`${path}/reclaim`, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  closeSync(claim);
  let owner: { version?: number; pid?: number; start?: string; nonce?: string };
  try {
    owner = JSON.parse(readFileSync(`${path}/owner`, "utf8")) as typeof owner;
  } catch {
    throw new Error("corrupt journal lock identity");
  }
  if (owner.version !== 1 || !Number.isSafeInteger(owner.pid) || typeof owner.start !== "string" || !exactHex(owner.nonce, 16)) {
    throw new Error("corrupt journal lock identity");
  }
  const observed = processStartToken(owner.pid!);
  if (observed === owner.start) {
    rmSync(`${path}/reclaim`);
    throw new Error("acceptance journal already owned");
  }
  const tombstone = `${path}.stale-${nonce}`;
  renameSync(path, tombstone);
  rmSync(tombstone, { recursive: true });
  return acquireProcessLock(path);
}

export class AcceptanceJournal {
  readonly #path: string;
  readonly #binding: InstanceBinding;
  readonly #messages = new Map<string, { message: AcceptedMessage; delivered: boolean }>();
  readonly #events: Array<{ sequence: bigint; payload: string }> = [];
  readonly #hierarchyResults = new Map<string, { commandSemantic: string; resultSemantic: string }>();
  readonly #lockPath: string;
  readonly #lockNonce: string;
  readonly #fault: JournalFaultHook | undefined;
  readonly #faultController: JournalFaultController | undefined;
  #closed = false;

  private constructor(path: string, binding: InstanceBinding, lockPath: string, lockNonce: string, fault?: JournalFaultHook, faultController?: JournalFaultController) {
    this.#path = path;
    this.#binding = binding;
    this.#lockPath = lockPath;
    this.#lockNonce = lockNonce;
    this.#fault = fault;
    this.#faultController = faultController;
  }

  static async open(path: string, binding: InstanceBinding, fault?: JournalFaultHook, faultController?: JournalFaultController): Promise<AcceptanceJournal> {
    if (!validateBinding(binding)) throw new Error("invalid acceptance journal binding");
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    const lockPath = `${path}.lock`;
    const lockNonce = acquireProcessLock(lockPath);
    const journal = new AcceptanceJournal(path, binding, lockPath, lockNonce, fault, faultController);
    try {
      let contents = "";
      try {
        const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
        try {
          const size = fstatSync(descriptor).size;
          if (size > MAX_JOURNAL_BYTES) throw new Error("acceptance journal capacity exceeded");
          const bounded = Buffer.alloc(MAX_JOURNAL_BYTES + 1);
          let offset = 0;
          for (;;) {
            const count = readSync(descriptor, bounded, offset, bounded.length - offset, null);
            offset += count;
            if (offset > MAX_JOURNAL_BYTES) throw new Error("acceptance journal capacity exceeded");
            if (count === 0) break;
          }
          contents = new TextDecoder("utf-8", { fatal: true }).decode(bounded.subarray(0, offset));
        } finally { closeSync(descriptor); }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
      const complete = contents.endsWith("\n") ? contents : contents.slice(0, Math.max(0, contents.lastIndexOf("\n") + 1));
      const hadTornTail = complete.length !== contents.length;
      const lines = complete.split("\n").filter((line) => line.length !== 0);
      if (lines.length > MAX_JOURNAL_RECORDS) throw new Error("acceptance journal record capacity exceeded");
      let sawBinding = false;
      for (const line of lines) {
      if (line.length === 0) continue;
      const decoded = JSON.parse(line, (_key, value: unknown) =>
        typeof value === "string" && /^\d+n$/.test(value) ? BigInt(value.slice(0, -1)) : value
      ) as JournalRecord;
      // Version 3 binds hierarchy results to the exact command event. Earlier
      // formats cannot prove that relationship and therefore fail closed.
      if (typeof decoded !== "object" || decoded === null || decoded.version !== 3) {
        throw new Error("incompatible acceptance journal format");
      }
      if (!validateBinding(decoded.binding) || !stableBinding(decoded.binding, binding)) {
        throw new Error("acceptance journal identity mismatch");
      }
      if (decoded.kind === "binding") {
        if (sawBinding || journal.#messages.size !== 0 || journal.#events.length !== 0 || journal.#hierarchyResults.size !== 0) throw new Error("invalid binding record order");
        sawBinding = true;
      } else if (!sawBinding) {
        throw new Error("acceptance journal lacks binding record");
      } else if (decoded.kind === "pending") {
        if (!exactHex(decoded.message?.messageId, 16) || !exactHex(decoded.message?.deliveryAttemptId, 16)
          || (decoded.message.operationId !== null && !exactHex(decoded.message.operationId, 16))
          || typeof decoded.message.canonicalPayload !== "string"
          || !exactHex(decoded.message.causeEnvelopeId, 16)) throw new Error("invalid pending record");
        const previous = journal.#messages.get(decoded.message.messageId);
        if (previous !== undefined && JSON.stringify(previous.message) !== JSON.stringify(decoded.message)) {
          throw new Error("message identity replay conflict");
        }
        journal.#messages.set(decoded.message.messageId, { message: decoded.message, delivered: false });
      } else if (decoded.kind === "delivered") {
        const previous = journal.#messages.get(decoded.messageId);
        if (previous === undefined) throw new Error("delivered marker lacks pending inbox record");
        previous.delivered = true;
      } else if (decoded.kind === "event") {
        if (typeof decoded.sequence !== "string" || !/^\d+$/.test(decoded.sequence) || typeof decoded.payload !== "string") throw new Error("invalid event record");
        const sequence = BigInt(decoded.sequence);
        if (sequence <= 0n || journal.#events.some((event) => event.sequence === sequence)) throw new Error("invalid event journal sequence");
        journal.#events.push({ sequence, payload: decoded.payload });
      } else if (decoded.kind === "hierarchy_result") {
        if (!exactHex(decoded.requestId, 16) || typeof decoded.commandSemantic !== "string" || decoded.commandSemantic.length === 0
          || typeof decoded.resultSemantic !== "string" || decoded.resultSemantic.length === 0) throw new Error("invalid hierarchy result record");
        validateHierarchyCommandSemantic(journal.#events, decoded.requestId, decoded.commandSemantic);
        validateHierarchyResultSemantic(binding, decoded.requestId, decoded.resultSemantic);
        const previous = journal.#hierarchyResults.get(decoded.requestId);
        if (previous !== undefined && (previous.commandSemantic !== decoded.commandSemantic || previous.resultSemantic !== decoded.resultSemantic)) {
          throw new Error("hierarchy result replay conflict");
        }
        journal.#hierarchyResults.set(decoded.requestId, {
          commandSemantic: decoded.commandSemantic, resultSemantic: decoded.resultSemantic,
        });
      } else {
        throw new Error("unknown acceptance journal record");
      }
      }
      if (hadTornTail) {
        const descriptor = openSync(path, constants.O_WRONLY | constants.O_NOFOLLOW);
        try { ftruncateSync(descriptor, Buffer.byteLength(complete)); fsyncSync(descriptor); } finally { closeSync(descriptor); }
      }
      if (lines.length === 0) {
      appendDurably(path, { version: 3, kind: "binding", binding });
      const directory = openSync(dirname(path), "r");
      try { fsyncSync(directory); } finally { closeSync(directory); }
      }
      return journal;
    } catch (error) {
      journal.close();
      throw error;
    }
  }

  get(messageId: string): { message: AcceptedMessage; delivered: boolean } | undefined {
    return this.#messages.get(messageId);
  }

  commitPending(record: AcceptedMessage): "pending" | "delivered" {
    const previous = this.#messages.get(record.messageId);
    if (previous !== undefined) {
      const { causeEnvelopeId: _priorCause, ...priorSemantic } = previous.message;
      const { causeEnvelopeId: _replayCause, ...replaySemantic } = record;
      if (JSON.stringify(priorSemantic) !== JSON.stringify(replaySemantic)) {
        throw new JournalConflictError("message identity replay conflict");
      }
      return previous.delivered ? "delivered" : "pending";
    }
    appendDurably(this.#path, { version: 3, kind: "pending", binding: this.#binding, message: record }, undefined,
      this.#faultController, { messageId: record.messageId, deliveryAttemptId: record.deliveryAttemptId });
    this.#messages.set(record.messageId, { message: record, delivered: false });
    return "pending";
  }

  markDelivered(messageId: string): void {
    const value = this.#messages.get(messageId);
    if (value === undefined) throw new Error("missing pending inbox record");
    if (value.delivered) return;
    appendDurably(this.#path, { version: 3, kind: "delivered", binding: this.#binding, messageId });
    value.delivered = true;
  }

  events(): ReadonlyArray<{ sequence: bigint; payload: string }> {
    return this.#events;
  }

  acceptedMessages(): AcceptedMessage[] {
    return [...this.#messages.values()].map((value) => value.message);
  }

  pendingMessages(): AcceptedMessage[] {
    return [...this.#messages.values()].filter((value) => !value.delivered).map((value) => value.message);
  }

  appendEvent(sequence: bigint, payload: string): void {
    if (sequence <= 0n || this.#events.some((event) => event.sequence === sequence)) throw new JournalConflictError("event sequence conflict");
    appendDurably(this.#path, { version: 3, kind: "event", binding: this.#binding, sequence: sequence.toString(), payload }, this.#fault);
    this.#events.push({ sequence, payload });
  }

  hierarchyResult(requestId: string, commandSemantic: string): string | undefined {
    const result = this.#hierarchyResults.get(requestId);
    if (result === undefined) return undefined;
    if (result.commandSemantic !== commandSemantic) throw new JournalConflictError("hierarchy result command conflict");
    return result.resultSemantic;
  }

  recordHierarchyResult(requestId: string, commandSemantic: string, resultSemantic: string): "recorded" | "replayed" {
    validateHierarchyCommandSemantic(this.#events, requestId, commandSemantic);
    validateHierarchyResultSemantic(this.#binding, requestId, resultSemantic);
    const previous = this.#hierarchyResults.get(requestId);
    if (previous !== undefined) {
      if (previous.commandSemantic !== commandSemantic || previous.resultSemantic !== resultSemantic) throw new JournalConflictError("hierarchy result replay conflict");
      return "replayed";
    }
    appendDurably(this.#path, { version: 3, kind: "hierarchy_result", binding: this.#binding, requestId, commandSemantic, resultSemantic });
    this.#hierarchyResults.set(requestId, { commandSemantic, resultSemantic });
    return "recorded";
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    try {
      const owner = JSON.parse(readFileSync(`${this.#lockPath}/owner`, "utf8")) as { nonce?: string };
      if (owner.nonce !== this.#lockNonce) throw new Error("journal lock ownership mismatch");
      const tombstone = `${this.#lockPath}.release-${this.#lockNonce}`;
      renameSync(this.#lockPath, tombstone);
      rmSync(tombstone, { recursive: true });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
}

export class PiAdapter {
  readonly #binding: InstanceBinding;
  readonly #session: PiSession;
  readonly #journal: AcceptanceJournal;
  readonly #bridge: NavigatorToolBridge | undefined;
  readonly #deliveryObserver: ((line: string) => void) | undefined;
  #closed = false;
  #pending = 0;
  readonly #scheduled = new Set<string>();
  #tail: Promise<void> = Promise.resolve();
  #lastContext: import("./tools.js").DeliveryContext | undefined;

  constructor(binding: InstanceBinding, session: PiSession, journal: AcceptanceJournal, bridge?: NavigatorToolBridge, deliveryObserver?: (line: string) => void, readonly implicitTerminalText = false) {
    this.#binding = binding;
    this.#session = session;
    this.#journal = journal;
    this.#bridge = bridge;
    this.#deliveryObserver = deliveryObserver;
    const last = journal.acceptedMessages().at(-1);
    this.#lastContext = last?.operationId === null ? undefined : last === undefined ? undefined : {
      operationId: Buffer.from(last.operationId, "hex"), messageId: Buffer.from(last.messageId, "hex"),
      deliveryAttemptId: Buffer.from(last.deliveryAttemptId, "hex"),
      inReplyTo: Buffer.from(last.causeEnvelopeId, "hex"),
    };
  }

  identity(): InstanceBinding {
    return this.#binding;
  }

  persistedEvents(): ReadonlyArray<{ sequence: bigint; payload: string }> { return this.#journal.events(); }
  acceptedMessages(): AcceptedMessage[] { return this.#journal.acceptedMessages(); }
  hasAcceptedOperation(operationId: string): boolean {
    return this.#journal.acceptedMessages().some((message) => message.operationId === operationId);
  }
  pendingMessages(): AcceptedMessage[] { return this.#journal.pendingMessages(); }
  appendEvent(sequence: bigint, payload: string): void { this.#journal.appendEvent(sequence, payload); }
  hierarchyResult(requestId: string, commandSemantic: string): string | undefined { return this.#journal.hierarchyResult(requestId, commandSemantic); }
  deliveryContext(): import("./tools.js").DeliveryContext | undefined { return this.#lastContext; }
  recordHierarchyResult(requestId: string, commandSemantic: string, resultSemantic: string): "recorded" | "replayed" {
    return this.#journal.recordHierarchyResult(requestId, commandSemantic, resultSemantic);
  }

  acceptance(messageId: string, deliveryAttemptId: string): "accepted" | "not_accepted" | "unknown" {
    const accepted = this.#journal.get(messageId);
    if (accepted === undefined) return "not_accepted";
    if (accepted.message.deliveryAttemptId !== deliveryAttemptId) return "unknown";
    return "accepted";
  }

  async deliver(record: AcceptedMessage, prompt: string): Promise<"accepted" | "replayed"> {
    if (this.#closed) throw new Error("adapter stopped");
    if (Buffer.byteLength(prompt) > MAX_FRAME_BYTES) throw new Error("payload exceeds bound");
    const existing = this.#journal.get(record.messageId);
    if (existing === undefined && this.#pending >= MAX_PENDING_DELIVERIES) throw new Error("delivery capacity exceeded");
    const disposition = this.#journal.commitPending(record);
    const durable = this.#journal.get(record.messageId)!.message;
    if (durable.operationId !== null) this.#lastContext = {
      operationId: Buffer.from(durable.operationId, "hex"), messageId: Buffer.from(durable.messageId, "hex"),
      deliveryAttemptId: Buffer.from(durable.deliveryAttemptId, "hex"),
      inReplyTo: Buffer.from(durable.causeEnvelopeId, "hex"),
    };
    if (disposition === "delivered") return "replayed";
    if (this.#scheduled.has(record.messageId)) return "replayed";
    if (this.#pending >= MAX_PENDING_DELIVERIES) return "replayed";
    this.#pending += 1;
    this.#scheduled.add(record.messageId);
    const run = this.#tail.then(async () => {
      if (this.#closed) throw new Error("adapter stopped");
      if (disposition === "pending") {
        if (durable.operationId === null) throw new Error("delivery operation identity missing");
        this.#bridge?.setActive(true, {
          operationId: Buffer.from(durable.operationId, "hex"),
          messageId: Buffer.from(durable.messageId, "hex"),
          deliveryAttemptId: Buffer.from(durable.deliveryAttemptId, "hex"),
          inReplyTo: Buffer.from(durable.causeEnvelopeId, "hex"),
        });
        try {
          this.#deliveryObserver?.(JSON.stringify({
            messageId: durable.messageId,
            deliveryAttemptId: durable.deliveryAttemptId,
            sha256: createHash("sha256").update(prompt).digest("hex"),
          }));
          await this.#session.prompt(prompt);
          if (this.implicitTerminalText && this.#bridge !== undefined && !this.#bridge.terminalReported()) {
            const text = this.#session.lastAssistantText().trim();
            if (text.length === 0) throw new Error("implicit terminal report lacks assistant text");
            await this.#bridge.report("succeeded", text);
          }
        } finally {
          this.#bridge?.setActive(false);
        }
          this.#journal.markDelivered(durable.messageId);
      }
    });
    this.#tail = run.then(() => undefined, () => undefined).finally(() => {
      this.#pending -= 1;
      this.#scheduled.delete(record.messageId);
    });
    return "accepted";
  }

  async cancel(): Promise<void> {
    if (!this.#closed) await this.#session.abort();
  }

  async remind(): Promise<void> {
    if (this.#closed) throw new Error("instance is stopped");
    await this.#session.steer("Navigator reminder: report progress or a terminal result using the authenticated protocol.");
  }

  async interactiveLine(line: string): Promise<void> {
    if (this.#closed) throw new Error("instance is stopped");
    if (Buffer.byteLength(line) > 64 * 1024) throw new Error("interactive line exceeds bound");
    const run = this.#tail.then(async () => {
      // Terminal input shares the Pi Session but is not an Operation delivery and
      // therefore cannot exercise report authority.
      if (this.#lastContext === undefined) throw new Error("interactive turn lacks a durable Navigator cause");
      this.#bridge?.setActive(true, this.#lastContext, false);
      try { await this.#session.prompt(line); } finally { this.#bridge?.setActive(false); }
    });
    this.#tail = run.catch(() => undefined);
    await run;
  }

  async stop(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    await this.#session.abort();
    await this.#session.dispose();
    this.#journal.close();
  }
}

export function captureCredential(environment: NodeJS.ProcessEnv, name = "NAVIGATOR_CREDENTIAL_FILE"): Buffer {
  const path = environment[name];
  delete environment[name];
  if (path === undefined || path.length === 0) throw new Error("missing credential file");
  const credential = readFileSync(path);
  if (credential.length < 32 || credential.length > 4096) throw new Error("invalid credential bound");
  return credential;
}

export async function stopOnOwnershipEof(
  ownership: NodeJS.ReadableStream,
  adapter: PiAdapter,
  timeoutMs: number,
): Promise<void> {
  ownership.resume();
  await new Promise<void>((resolve) => {
    ownership.once("end", resolve);
    ownership.once("error", resolve);
    ownership.once("close", resolve);
  });
  await Promise.race([
    adapter.stop(),
    new Promise<never>((_resolve, reject) => {
      setTimeout(() => reject(new Error("ownership cleanup timeout")), timeoutMs);
    }),
  ]);
}
