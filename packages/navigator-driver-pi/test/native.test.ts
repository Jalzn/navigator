import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { appendFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { fauxAssistantMessage, fauxProvider, fauxToolCall } from "@earendil-works/pi-ai";
import { ModelRuntime } from "@earendil-works/pi-coding-agent";
import { createNativePiSession, PROVEN_PI_CAPABILITIES } from "../src/native.js";
import { NavigatorToolBridge } from "../src/tools.js";
import { admitPendingTool, trustedToolCatalog } from "../src/server.js";
import { AcceptanceJournal, type InstanceBinding } from "../src/adapter.js";
import { PiAdapter } from "../src/adapter.js";

test("native Pi session is headless, isolated, and settlement is not a Navigator result", async () => {
  const directory = await mkdtemp(join(tmpdir(), "navigator-native-pi-"));
  const faux = fauxProvider({ tokensPerSecond: 1_000 });
  const runtime = await ModelRuntime.create({
    authPath: join(directory, "auth.json"),
    modelsPath: null,
    allowModelNetwork: false,
    refreshOnCreate: false,
  });
  runtime.registerNativeProvider(faux.provider);
  const session = await createNativePiSession({
    cwd: directory,
    sessionFile: join(directory, "sessions", "attempt.jsonl"),
    baseInstructions: "Navigator Worker fixture",
    tools: [],
  }, runtime, faux.getModel());
  try {
    faux.setResponses([fauxAssistantMessage("settled")]);
    const events: unknown[] = [];
    const unsubscribe = session.subscribe((event) => events.push(event));
    await session.prompt("bounded task");
    unsubscribe();
    assert.ok(events.some((event) =>
      typeof event === "object" && event !== null && "type" in event && event.type === "agent_end"
    ));
    assert.equal(events.some((event) =>
      typeof event === "object" && event !== null && "navigatorResult" in event
    ), false);
    assert.equal(PROVEN_PI_CAPABILITIES.includes("interactive-terminal.v1"), false);
    await session.dispose();
    const persisted = await readFile(join(directory, "sessions", "attempt.jsonl"), "utf8");
    assert.match(persisted, /bounded task/);
    const reopened = await createNativePiSession({
      cwd: directory,
      sessionFile: join(directory, "sessions", "attempt.jsonl"),
      baseInstructions: "Navigator Worker fixture",
      tools: [],
    }, runtime, faux.getModel());
    try {
      assert.equal((reopened as { sessionFile?: string }).sessionFile,
        join(directory, "sessions", "attempt.jsonl"));
    } finally {
      await reopened.dispose();
    }
  } finally {
    await Promise.resolve(session.dispose()).catch(() => undefined);
    await rm(directory, { recursive: true, force: true });
  }
});

test("native Pi executes the Navigator report tool only through the injected bridge", async () => {
  const directory = await mkdtemp(join(tmpdir(), "navigator-native-report-"));
  const faux = fauxProvider({ tokensPerSecond: 1_000 });
  const runtime = await ModelRuntime.create({ modelsPath: null, allowModelNetwork: false, refreshOnCreate: false });
  runtime.registerNativeProvider(faux.provider);
  const reports: string[] = [];
  const bridge = new NavigatorToolBridge(async (report) => {
    reports.push(`${report.kind}:${new TextDecoder().decode(report.payload)}`);
  });
  const session = await createNativePiSession({
    cwd: directory,
    sessionFile: join(directory, "session.jsonl"),
    baseInstructions: "Report through Navigator.",
    tools: [],
  }, runtime, faux.getModel(), bridge);
  try {
    bridge.setActive(true, {
      operationId: Buffer.alloc(16, 1),
      messageId: Buffer.alloc(16, 2),
      deliveryAttemptId: Buffer.alloc(16, 4),
      inReplyTo: Buffer.alloc(16, 3),
    });
    faux.setResponses([
      fauxAssistantMessage(fauxToolCall("navigator_report", { kind: "succeeded", payload: "done" }), { stopReason: "toolUse" }),
      fauxAssistantMessage("settled"),
    ]);
    await session.prompt("work");
    assert.deepEqual(reports, ["succeeded:done"]);
  } finally {
    bridge.setActive(false);
    await session.dispose();
    await rm(directory, { recursive: true, force: true });
  }
});

test("native Pi executes an authenticated hierarchy tool through its waiter bridge", async () => {
  const directory = await mkdtemp(join(tmpdir(), "navigator-native-hierarchy-"));
  const faux = fauxProvider({ tokensPerSecond: 1_000 });
  const runtime = await ModelRuntime.create({ modelsPath: null, allowModelNetwork: false, refreshOnCreate: false });
  runtime.registerNativeProvider(faux.provider);
  const calls: string[] = [];
  const bridge = new NavigatorToolBridge(async () => undefined, async (command) => {
    calls.push(`${Buffer.from(command.requestId).toString("hex")}:${command.grantId.length}`); return "spawn committed";
  });
  const session = await createNativePiSession({ cwd: directory, sessionFile: join(directory, "session.jsonl"), baseInstructions: "Spawn.", tools: [] }, runtime, faux.getModel(), bridge);
  try {
    bridge.setActive(true);
    faux.setResponses([
      fauxAssistantMessage(fauxToolCall("navigator_spawn_child", { request_id: "11".repeat(16), template_id: "22".repeat(16), task_input_base64: "e30=" }), { stopReason: "toolUse" }),
      fauxAssistantMessage("settled"),
    ]);
    await session.prompt("spawn");
    assert.deepEqual(calls, [`${"11".repeat(16)}:0`]);
  } finally { bridge.setActive(false); await session.dispose(); await rm(directory, { recursive: true, force: true }); }
});

test("trusted Tool catalog exposes only fixed registrations and rejects catalog downgrade", async () => {
  const encoded = (name: string) => Buffer.from(JSON.stringify({ navigator_tool_catalog: [{ registration_id: "07".repeat(16), name, version: "V1", input_schema: { type: "object" } }] }));
  assert.equal(trustedToolCatalog(encoded("Records.Lookup"))[0]?.name, "Records.Lookup");
  assert.deepEqual(trustedToolCatalog(Buffer.from(JSON.stringify({ navigator_tool_catalog: [] }))), []);
  for (const malformed of [
    Buffer.from("not-json"),
    Buffer.from("null"),
    Buffer.from("[]"),
    Buffer.from("{}"),
    Buffer.from(JSON.stringify({ navigator_tool_catalog: {} })),
  ]) assert.throws(() => trustedToolCatalog(malformed));
  for (const invalid of ["bad@name", "éclair", "has space", ".leading", "trailing-"]) assert.throws(() => trustedToolCatalog(encoded(invalid)));
  for (const malformed of [
    { registration_id: "00".repeat(16), name: "Records.Lookup", version: "V1", input_schema: { type: "object" } },
    { registration_id: "07".repeat(16), name: "Records.Lookup", version: "V1", input_schema: { type: "object" }, selector: "arbitrary" },
    { registration_id: "07".repeat(16), name: "Records.Lookup", version: "V1", input_schema: { type: "object", arbitrary: true } },
  ]) assert.throws(() => trustedToolCatalog(Buffer.from(JSON.stringify({ navigator_tool_catalog: [malformed] }))));
  const bridge = new NavigatorToolBridge(
    async () => undefined,
    async () => { throw new Error("unused"); },
    async () => { throw new Error("unused"); },
    async () => { throw new Error("unused"); },
    async () => { throw new Error("unused"); },
    async () => ({
      outputBase64: Buffer.from('{"status":"committed"}').toString("base64"),
      artifacts: [{
        artifactId: "08".repeat(16), sessionId: "09".repeat(16),
        creatorParticipantId: "0a".repeat(16), creatorOperationId: "0b".repeat(16),
        mediaType: "application/octet-stream", size: "3", sha256: "0c".repeat(32),
      }],
    }),
  );
  bridge.configureToolCatalog([{ registrationId: Buffer.alloc(16, 7), name: "Records.Lookup", version: "V1", inputSchema: { type: "object", additionalProperties: false } }]);
  const names = bridge.tools().map((tool) => tool.name);
  assert(names.includes(`navigator_registered_tool_${"07".repeat(16)}`));
  assert(!names.includes("Records.Lookup"));
  assert(!names.includes("untrusted.tool"));
  bridge.setActive(true, {
    operationId: Buffer.alloc(16, 1), messageId: Buffer.alloc(16, 2),
    deliveryAttemptId: Buffer.alloc(16, 3), inReplyTo: Buffer.alloc(16, 4),
  });
  const registered = bridge.tools().find((tool) => tool.name === `navigator_registered_tool_${"07".repeat(16)}`);
  assert(registered !== undefined);
  const invoke = registered.execute as (...arguments_: unknown[]) => Promise<{ content: Array<{ type: string; text?: string }>; details: unknown }>;
  const observed = await invoke("call-1", {});
  assert.equal(observed.content[0]?.type, "text");
  assert.equal(observed.content[0]?.text, '{"status":"committed"}');
  assert.deepEqual(observed.details, { artifacts: [{
    artifactId: "08".repeat(16), sessionId: "09".repeat(16),
    creatorParticipantId: "0a".repeat(16), creatorOperationId: "0b".repeat(16),
    mediaType: "application/octet-stream", size: "3", sha256: "0c".repeat(32),
  }] });
  const command = bridge.tools().find((tool) => tool.name === "navigator_command");
  assert(command !== undefined);
  assert(!JSON.stringify(command.parameters).includes('"tool"'));
  assert.throws(() => bridge.configureToolCatalog([{ registrationId: Buffer.alloc(16, 7), name: "Records.Lookup", version: "V0", inputSchema: { type: "object" } }]));

  const emptyBridge = new NavigatorToolBridge(async () => undefined);
  emptyBridge.configureToolCatalog([]);
  assert.throws(() => emptyBridge.configureToolCatalog([{ registrationId: Buffer.alloc(16, 7), name: "Records.Lookup", version: "V1", inputSchema: { type: "object" } }]));

  const bounded = (count: number) => Buffer.from(JSON.stringify({
    navigator_tool_catalog: Array.from({ length: count }, (_, index) => ({
      registration_id: (index + 1).toString(16).padStart(32, "0"),
      name: `Tool.${index}`,
      version: "V1",
      input_schema: { type: "object" },
    })),
  }));
  assert.equal(trustedToolCatalog(bounded(64)).length, 64);
  assert.throws(() => trustedToolCatalog(bounded(65)));
  admitPendingTool(127);
  assert.throws(() => admitPendingTool(128));
  assert.throws(() => admitPendingTool(129));
});

test("native abort observer fires at the real session boundary without changing abort", async () => {
  const directory = await mkdtemp(join(tmpdir(), "navigator-native-abort-observer-"));
  const observed = join(directory, "abort-observed");
  const faux = fauxProvider({ tokensPerSecond: 1_000 });
  const runtime = await ModelRuntime.create({ modelsPath: null, allowModelNetwork: false, refreshOnCreate: false });
  runtime.registerNativeProvider(faux.provider);
  const session = await createNativePiSession({ cwd: directory, sessionFile: join(directory, "session.jsonl"), baseInstructions: "Abort.", tools: [] }, runtime, faux.getModel(), undefined, {
    onAbort: () => { appendFileSync(observed, "abort\n"); },
  });
  try {
    await session.abort();
    await session.abort();
    assert.equal(await readFile(observed, "utf8"), "abort\nabort\n",
      "native abort must remain safely re-executable after an in-memory Cancel state is lost");
  } finally { await session.dispose(); await rm(directory, { recursive: true, force: true }); }
});

test("native prompt observer exposes only the digest at the real prompt boundary", async () => {
  const directory = await mkdtemp(join(tmpdir(), "navigator-native-prompt-observer-"));
  const faux = fauxProvider({ tokensPerSecond: 1_000 });
  const runtime = await ModelRuntime.create({ modelsPath: null, allowModelNetwork: false, refreshOnCreate: false });
  runtime.registerNativeProvider(faux.provider);
  const digests: string[] = [];
  const session = await createNativePiSession({ cwd: directory, sessionFile: join(directory, "session.jsonl"), baseInstructions: "Prompt.", tools: [] }, runtime, faux.getModel(), undefined, {
    onPrompt: (digest) => digests.push(digest),
  });
  try {
    faux.setResponses([fauxAssistantMessage("settled")]);
    await session.prompt("secret prompt body");
    assert.deepEqual(digests, [createHash("sha256").update("secret prompt body").digest("hex")]);
    assert.doesNotMatch(digests.join(""), /secret prompt body/);
  } finally { await session.dispose(); await rm(directory, { recursive: true, force: true }); }
});

test("durable Deliver ACK can be followed immediately by exact-operation Cancel after settlement", async () => {
  const directory = await mkdtemp(join(tmpdir(), "navigator-native-deliver-cancel-"));
  const faux = fauxProvider({ tokensPerSecond: 1_000 });
  const runtime = await ModelRuntime.create({ modelsPath: null, allowModelNetwork: false, refreshOnCreate: false });
  runtime.registerNativeProvider(faux.provider);
  const binding: InstanceBinding = { driverId: "01".repeat(16), sessionId: "02".repeat(16), participantId: "03".repeat(16), launchAttemptId: "04".repeat(16), instanceId: "05".repeat(16), ownershipEpoch: 7n };
  const session = await createNativePiSession({ cwd: directory, sessionFile: join(directory, "session.jsonl"), baseInstructions: "Settle.", tools: [] }, runtime, faux.getModel());
  const adapter = new PiAdapter(binding, session, await AcceptanceJournal.open(join(directory, "journal"), binding));
  try {
    faux.setResponses([fauxAssistantMessage("settled")]);
    assert.equal(await adapter.deliver({ messageId: "11".repeat(16), deliveryAttemptId: "12".repeat(16), operationId: "13".repeat(16), canonicalPayload: "exact", causeEnvelopeId: "14".repeat(16) }, "work"), "accepted");
    await adapter.cancel();
  } finally { await adapter.stop(); await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 20 }); }
});

test("native Pi crash window after hierarchy result fsync has no transcript proof", async () => {
  const directory = await mkdtemp(join(tmpdir(), "navigator-native-hierarchy-crash-"));
  const sessionFile = join(directory, "session.jsonl");
  const journalPath = join(directory, "journal");
  const binding: InstanceBinding = {
    driverId: "01".repeat(16), sessionId: "02".repeat(16), participantId: "03".repeat(16),
    launchAttemptId: "04".repeat(16), instanceId: "05".repeat(16), ownershipEpoch: 7n,
  };
  const requestId = "31".repeat(16);
  const worker = fileURLToPath(new URL("./native-hierarchy-crash-worker.ts", import.meta.url));
  const crashed = spawnSync(process.execPath, ["--import", "tsx", worker, directory]);
  assert.equal(crashed.status, 83, crashed.stderr.toString());
  assert.doesNotMatch(await readFile(sessionFile, "utf8"), /Navigator hierarchy spawned committed/);
  const reopened = await AcceptanceJournal.open(journalPath, binding);
  assert.equal(reopened.events().length, 1);
  assert.ok(reopened.hierarchyResult(requestId, reopened.events()[0]!.payload));
  reopened.close();
  await rm(directory, { recursive: true, force: true });
});
