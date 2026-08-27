import assert from "node:assert/strict";
import { appendFile, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import {
  AcceptanceJournal,
  PiAdapter,
  captureCredential,
  stopOnOwnershipEof,
  type InstanceBinding,
  type PiSession,
} from "../src/adapter.js";
import { NavigatorToolBridge } from "../src/tools.js";
import { create, toBinary } from "@bufbuild/protobuf";
import { DriverEventSchema, HierarchyCommandSchema, HierarchyResultRequestSchema, InstanceIdentitySchema, SpawnChildCommandSchema, SpawnChildResultSchema } from "@navigator/driver-protocol/gen/navigator/driver/v1/driver_pb.js";

const binding: InstanceBinding = {
  driverId: "01".repeat(16),
  sessionId: "02".repeat(16),
  participantId: "03".repeat(16),
  launchAttemptId: "04".repeat(16),
  instanceId: "05".repeat(16),
  ownershipEpoch: 7n,
};

function hierarchySemantics(requestId: string): { command: string; result: string } {
  const instance = create(InstanceIdentitySchema, {
    driverId: Buffer.from(binding.driverId, "hex"), sessionId: Buffer.from(binding.sessionId, "hex"),
    participantId: Buffer.from(binding.participantId, "hex"), launchAttemptId: Buffer.from(binding.launchAttemptId, "hex"),
    instanceId: Buffer.from(binding.instanceId, "hex"), ownershipEpoch: binding.ownershipEpoch,
  });
  const command = create(DriverEventSchema, { eventId: Buffer.alloc(16, 9), instance, sequence: 1n, inReplyTo: Buffer.alloc(16, 8), event: { case: "hierarchyCommand", value: create(HierarchyCommandSchema, {
    requestId: Buffer.from(requestId, "hex"), command: { case: "spawnChild", value: create(SpawnChildCommandSchema, { templateId: Buffer.alloc(16, 7) }) },
  }) } });
  const result = create(HierarchyResultRequestSchema, { instance, hierarchyRequestId: Buffer.from(requestId, "hex"), result: { case: "spawned", value: create(SpawnChildResultSchema, { participantId: Buffer.alloc(16, 6), operationId: Buffer.alloc(16, 5), inputMessageId: Buffer.alloc(16, 4) }) } });
  return { command: Buffer.from(toBinary(DriverEventSchema, command)).toString("base64"), result: Buffer.from(toBinary(HierarchyResultRequestSchema, result)).toString("base64") };
}

class DeterministicPi implements PiSession {
  readonly prompts: string[] = [];
  aborts = 0;
  disposals = 0;

  async prompt(text: string): Promise<void> {
    this.prompts.push(text);
  }
  async steer(text: string): Promise<void> {
    this.prompts.push(text);
  }
  async abort(): Promise<void> {
    this.aborts += 1;
  }
  dispose(): void {
    this.disposals += 1;
  }
  subscribe(): () => void {
    return () => undefined;
  }
}

class FailingPi extends DeterministicPi {
  override async prompt(): Promise<void> {
    throw new Error("injected prompt failure");
  }
}

class FailingOnceAbortPi extends DeterministicPi {
  override async abort(): Promise<void> {
    this.aborts += 1;
    if (this.aborts === 1) throw new Error("injected abort failure");
  }
}

test("delivery observer binds message and attempt to prompt digest before native prompt", async () => {
  const directory = await mkdtemp(join(tmpdir(), "navigator-delivery-observer-"));
  const observed: string[] = [];
  class InspectingPi extends DeterministicPi {
    override async prompt(text: string): Promise<void> {
      assert.equal(observed.length, 1, "delivery observation did not precede native prompt");
      await super.prompt(text);
    }
  }
  const native = new InspectingPi();
  const adapter = new PiAdapter(binding, native, await AcceptanceJournal.open(join(directory, "journal"), binding), undefined,
    (line) => observed.push(line));
  const record = { messageId: "11".repeat(16), deliveryAttemptId: "12".repeat(16), operationId: "13".repeat(16), canonicalPayload: "canonical", causeEnvelopeId: "14".repeat(16) };
  await adapter.deliver(record, "prompt bytes");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(observed[0], JSON.stringify({ messageId: record.messageId, deliveryAttemptId: record.deliveryAttemptId,
    sha256: createHash("sha256").update("prompt bytes").digest("hex") }));
  await adapter.stop();
});

test("persists exact Navigator identity before ACK and reopens without Pi records", async () => {
  const directory = await mkdtemp(join(tmpdir(), "navigator-pi-"));
  const path = join(directory, "acceptance.jsonl");
  const native = new DeterministicPi();
  const journal = await AcceptanceJournal.open(path, binding);
  const adapter = new PiAdapter(binding, native, journal);
  const accepted = {
    messageId: "11".repeat(16),
    deliveryAttemptId: "12".repeat(16),
    operationId: "13".repeat(16),
    canonicalPayload: "canonical-1",
    causeEnvelopeId: "15".repeat(16),
  };
  assert.equal(await adapter.deliver(accepted, "work"), "accepted");
  assert.deepEqual(native.prompts, ["work"]);
  await assert.rejects(() => AcceptanceJournal.open(path, binding), /already owned/);
  await adapter.stop();
  const reopened = new PiAdapter(binding, new DeterministicPi(), await AcceptanceJournal.open(path, binding));
  assert.equal(reopened.acceptance("11".repeat(16), "12".repeat(16)), "accepted");
  assert.equal(reopened.acceptance("11".repeat(16), "14".repeat(16)), "unknown");
  assert.equal(await reopened.deliver(accepted, "work"), "replayed");
  await assert.rejects(() => reopened.deliver({ ...accepted, canonicalPayload: "changed" }, "work"));
  await reopened.stop();
});

test("credential capture removes inherited path and ownership EOF disposes bounded session", async () => {
  const directory = await mkdtemp(join(tmpdir(), "navigator-pi-secret-"));
  const path = join(directory, "credential");
  await writeFile(path, Buffer.alloc(32, 7), { mode: 0o600 });
  const environment: NodeJS.ProcessEnv = { NAVIGATOR_CREDENTIAL_FILE: path };
  assert.equal(captureCredential(environment).length, 32);
  assert.equal(environment.NAVIGATOR_CREDENTIAL_FILE, undefined);

  const native = new DeterministicPi();
  const adapter = new PiAdapter(
    binding,
    native,
    await AcceptanceJournal.open(join(directory, "journal"), binding),
  );
  const ownership = new PassThrough();
  const stopped = stopOnOwnershipEof(ownership, adapter, 1_000);
  ownership.end();
  await stopped;
  assert.equal(native.aborts, 1);
  assert.equal(native.disposals, 1);
  await assert.rejects(() => adapter.deliver({
    messageId: "late",
    deliveryAttemptId: "late-attempt",
    operationId: null,
    canonicalPayload: "canonical",
    causeEnvelopeId: "16".repeat(16),
  }, "late"));
});

test("identity mismatch and oversize input fail before native prompt", async () => {
  const directory = await mkdtemp(join(tmpdir(), "navigator-pi-bound-"));
  const path = join(directory, "journal");
  const native = new DeterministicPi();
  const journal = await AcceptanceJournal.open(path, binding);
  const adapter = new PiAdapter(binding, native, journal);
  await assert.rejects(() => adapter.deliver({
    messageId: "large",
    deliveryAttemptId: "attempt-large",
    operationId: null,
    canonicalPayload: "canonical",
    causeEnvelopeId: "17".repeat(16),
  }, "x".repeat(1024 * 1024 + 1)));
  assert.deepEqual(native.prompts, []);
  await assert.rejects(() => AcceptanceJournal.open(path, { ...binding, ownershipEpoch: 8n }));
});

test("reminder steers the active Pi session without manufacturing an outbound outcome", async () => {
  const directory = await mkdtemp(join(tmpdir(), "navigator-pi-reminder-"));
  const native = new DeterministicPi();
  const journal = await AcceptanceJournal.open(join(directory, "journal"), binding);
  const adapter = new PiAdapter(binding, native, journal);

  await adapter.remind();

  assert.deepEqual(native.prompts, [
    "Navigator reminder: report progress or a terminal result using the authenticated protocol.",
  ]);
  assert.deepEqual(adapter.persistedEvents(), []);
  await adapter.stop();
});

test("failed native abort is re-executable for a truthful Cancel retry", async () => {
  const directory = await mkdtemp(join(tmpdir(), "navigator-pi-cancel-retry-"));
  const native = new FailingOnceAbortPi();
  const adapter = new PiAdapter(binding, native, await AcceptanceJournal.open(join(directory, "journal"), binding));
  await assert.rejects(() => adapter.cancel(), /abort failure/);
  await adapter.cancel();
  assert.equal(native.aborts, 2);
  await adapter.stop();
});

test("prompt failure remains durably accepted and a reopened inbox retries execution", async () => {
  const directory = await mkdtemp(join(tmpdir(), "navigator-pi-pending-"));
  const path = join(directory, "journal");
  const message = {
    messageId: "21".repeat(16),
    deliveryAttemptId: "22".repeat(16),
    operationId: "23".repeat(16),
    canonicalPayload: "canonical-pending-deliver",
    causeEnvelopeId: "24".repeat(16),
  };
  const failed = new PiAdapter(binding, new FailingPi(), await AcceptanceJournal.open(path, binding));
  assert.equal(await failed.deliver(message, "retryable work"), "accepted");
  assert.equal(failed.acceptance(message.messageId, message.deliveryAttemptId), "accepted");
  await new Promise((resolve) => setImmediate(resolve));
  await failed.stop();

  const recoveredNative = new DeterministicPi();
  const recovered = new PiAdapter(
    binding,
    recoveredNative,
    await AcceptanceJournal.open(path, binding),
  );
  assert.equal(await recovered.deliver(message, "retryable work"), "accepted");
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(recoveredNative.prompts, ["retryable work"]);
  assert.equal(recovered.acceptance(message.messageId, message.deliveryAttemptId), "accepted");
  await recovered.stop();
});

test("serialized deliveries expose only their exact operation and message context", async () => {
  const directory = await mkdtemp(join(tmpdir(), "navigator-pi-context-"));
  const observed: string[] = [];
  let bridge!: NavigatorToolBridge;
  class ContextPi extends DeterministicPi {
    override async prompt(text: string): Promise<void> {
      await new Promise((resolve) => setImmediate(resolve));
      const context = bridge.context();
      assert.ok(context);
      observed.push(`${text}:${Buffer.from(context.operationId).toString("hex")}:${Buffer.from(context.messageId).toString("hex")}:${Buffer.from(context.inReplyTo).toString("hex")}`);
    }
  }
  bridge = new NavigatorToolBridge(async () => undefined);
  const adapter = new PiAdapter(binding, new ContextPi(), await AcceptanceJournal.open(join(directory, "journal"), binding), bridge);
  await Promise.all([
    adapter.deliver({ messageId: "11".repeat(16), deliveryAttemptId: "31".repeat(16), operationId: "21".repeat(16), canonicalPayload: "one", causeEnvelopeId: "51".repeat(16) }, "one"),
    adapter.deliver({ messageId: "12".repeat(16), deliveryAttemptId: "32".repeat(16), operationId: "22".repeat(16), canonicalPayload: "two", causeEnvelopeId: "52".repeat(16) }, "two"),
  ]);
  while (observed.length !== 2) await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(observed, [
    `one:${"21".repeat(16)}:${"11".repeat(16)}:${"51".repeat(16)}`,
    `two:${"22".repeat(16)}:${"12".repeat(16)}:${"52".repeat(16)}`,
  ]);
  assert.equal(bridge.context(), undefined);
  await adapter.stop();
});

test("durable inbox commit ACKs before a deliberately blocked Pi prompt settles", async () => {
  const directory = await mkdtemp(join(tmpdir(), "navigator-pi-early-ack-"));
  let entered!: () => void;
  const promptEntered = new Promise<void>((resolve) => { entered = resolve; });
  let release!: () => void;
  const blocked = new Promise<void>((resolve) => { release = resolve; });
  class BlockingPi extends DeterministicPi {
    override async prompt(): Promise<void> { entered(); await blocked; }
  }
  const adapter = new PiAdapter(binding, new BlockingPi(), await AcceptanceJournal.open(join(directory, "journal"), binding));
  const message = {
    messageId: "41".repeat(16), deliveryAttemptId: "42".repeat(16),
    operationId: "43".repeat(16), canonicalPayload: "canonical-blocked",
    causeEnvelopeId: "44".repeat(16),
  };
  assert.equal(await adapter.deliver(message, "blocked"), "accepted");
  await promptEntered;
  assert.equal(adapter.acceptance(message.messageId, message.deliveryAttemptId), "accepted");
  await assert.rejects(() => adapter.deliver({ ...message, canonicalPayload: "changed" }, "blocked"), /conflict/);
  release();
  await new Promise((resolve) => setImmediate(resolve));
  await adapter.stop();
});

test("outbound events and hierarchy result identities survive reopen exactly", async () => {
  const directory = await mkdtemp(join(tmpdir(), "navigator-pi-events-"));
  const path = join(directory, "journal");
  const first = await AcceptanceJournal.open(path, binding);
  const semantics = hierarchySemantics("31".repeat(16));
  first.appendEvent(1n, semantics.command);
  assert.equal(first.recordHierarchyResult("31".repeat(16), semantics.command, semantics.result), "recorded");
  first.close();
  const reopened = await AcceptanceJournal.open(path, binding);
  assert.deepEqual(reopened.events(), [{ sequence: 1n, payload: semantics.command }]);
  assert.equal(reopened.hierarchyResult("31".repeat(16), semantics.command), semantics.result);
  assert.equal(reopened.recordHierarchyResult("31".repeat(16), semantics.command, semantics.result), "replayed");
  assert.throws(() => reopened.recordHierarchyResult("31".repeat(16), "other-event", semantics.result), /prior command|conflict/);
  assert.throws(() => reopened.recordHierarchyResult("31".repeat(16), semantics.command, "changed"), /semantic|conflict/);
  reopened.close();
});

test("orphan, reordered, and malformed hierarchy results fail closed on reopen", async () => {
  const requestId = "31".repeat(16);
  const semantics = hierarchySemantics(requestId);
  for (const [name, records, expected] of [
    ["orphan", [{ kind: "hierarchy_result", requestId, commandSemantic: semantics.command, resultSemantic: semantics.result }], /lacks prior command/],
    ["reordered", [{ kind: "hierarchy_result", requestId, commandSemantic: semantics.command, resultSemantic: semantics.result }, { kind: "event", sequence: "1", payload: semantics.command }], /lacks prior command/],
    ["malformed", [{ kind: "event", sequence: "1", payload: semantics.command }, { kind: "hierarchy_result", requestId, commandSemantic: semantics.command, resultSemantic: "bm90LXByb3RvYnVm" }], /hierarchy result semantic/],
  ] as const) {
    const directory = await mkdtemp(join(tmpdir(), `navigator-pi-result-${name}-`));
    const path = join(directory, "journal");
    const journal = await AcceptanceJournal.open(path, binding); journal.close();
    for (const record of records) await appendFile(path, `${JSON.stringify({ version: 3, binding }, (_key, value: unknown) => typeof value === "bigint" ? `${value}n` : value).slice(0, -1)},${JSON.stringify(record).slice(1)}\n`);
    await assert.rejects(() => AcceptanceJournal.open(path, binding), expected);
  }
});

test("semantically empty hierarchy result is never appended", async () => {
  const directory = await mkdtemp(join(tmpdir(), "navigator-pi-empty-result-"));
  const path = join(directory, "journal");
  const requestId = "31".repeat(16);
  const semantics = hierarchySemantics(requestId);
  const journal = await AcceptanceJournal.open(path, binding);
  journal.appendEvent(1n, semantics.command);
  assert.throws(() => journal.recordHierarchyResult(requestId, semantics.command, ""), /hierarchy result semantic/);
  journal.close();
  const reopened = await AcceptanceJournal.open(path, binding);
  assert.equal(reopened.hierarchyResult(requestId, semantics.command), undefined);
  reopened.close();
});

test("subprocess crash around hierarchy Event fsync reopens prior-or-one with stable identity", async () => {
  for (const [point, expectedExit] of [["before_fsync", 81], ["after_fsync", 82]] as const) {
    const directory = await mkdtemp(join(tmpdir(), `navigator-pi-hierarchy-${point}-`));
    const path = join(directory, "journal");
    const worker = fileURLToPath(new URL("./hierarchy-crash-worker.ts", import.meta.url));
    const crashed = spawnSync(process.execPath, ["--import", "tsx", worker, path, point], { cwd: process.cwd() });
    assert.equal(crashed.status, expectedExit, crashed.stderr.toString());
    const reopened = await AcceptanceJournal.open(path, binding);
    const events = reopened.events();
    assert.ok(events.length <= 1);
    if (point === "after_fsync") assert.deepEqual(events, [{ sequence: 1n, payload: "stable-hierarchy-command" }]);
    if (events.length === 1) assert.deepEqual(events[0], { sequence: 1n, payload: "stable-hierarchy-command" });
    reopened.close();
  }
});

test("torn tail is truncated and closed corruption releases the process lock", async () => {
  const directory = await mkdtemp(join(tmpdir(), "navigator-pi-corrupt-"));
  const path = join(directory, "journal");
  const journal = await AcceptanceJournal.open(path, binding);
  journal.close();
  await appendFile(path, "{\"version\":3,\"kind\":\"event\"");
  const recovered = await AcceptanceJournal.open(path, binding);
  recovered.close();
  const encodedBinding = JSON.stringify(binding, (_key, value: unknown) => typeof value === "bigint" ? `${value}n` : value);
  await appendFile(path, `${JSON.stringify({ version: 3, kind: "alien" }).slice(0, -1)},\"binding\":${encodedBinding}}\n`);
  await assert.rejects(() => AcceptanceJournal.open(path, binding), /unknown/);
  await assert.rejects(() => AcceptanceJournal.open(path, binding), /unknown/);
});

test("old journal formats and missing or forged delivery causes fail closed on reopen", async () => {
  const record = {
    messageId: "81".repeat(16), deliveryAttemptId: "82".repeat(16), operationId: "83".repeat(16),
    canonicalPayload: "payload", causeEnvelopeId: "84".repeat(16),
  };
  for (const [name, mutate, expected] of [
    ["v2", (text: string) => text.replaceAll('"version":3', '"version":2'), /incompatible.*format/],
    ["missing", (text: string) => text.replace(`,\"causeEnvelopeId\":\"${"84".repeat(16)}\"`, ""), /invalid pending/],
    ["forged", (text: string) => text.replace("84".repeat(16), "gg".repeat(16)), /invalid pending/],
  ] as const) {
    const directory = await mkdtemp(join(tmpdir(), `navigator-pi-cause-${name}-`));
    const path = join(directory, "journal");
    const journal = await AcceptanceJournal.open(path, binding);
    journal.commitPending(record);
    journal.close();
    await writeFile(path, mutate(await readFile(path, "utf8")), { mode: 0o600 });
    await assert.rejects(() => AcceptanceJournal.open(path, binding), expected);
  }
});

test("two stale-lock reclaimers cannot delete the new owner lock", async () => {
  const directory = await mkdtemp(join(tmpdir(), "navigator-pi-lock-race-"));
  const path = join(directory, "journal");
  const crashWorker = fileURLToPath(new URL("./hierarchy-crash-worker.ts", import.meta.url));
  assert.equal(spawnSync(process.execPath, ["--import", "tsx", crashWorker, path, "after_fsync"]).status, 82);
  const worker = fileURLToPath(new URL("./lock-race-worker.ts", import.meta.url));
  const winners = join(directory, "winners");
  const run = (): Promise<number | null> => new Promise((resolve) => {
    const child = spawn(process.execPath, ["--import", "tsx", worker, path, winners], { stdio: "ignore" });
    child.once("exit", resolve);
  });
  const statuses = await Promise.all([run(), run()]);
  assert.deepEqual(statuses.sort(), [0, 75]);
  const final = await AcceptanceJournal.open(path, binding);
  final.close();
});
