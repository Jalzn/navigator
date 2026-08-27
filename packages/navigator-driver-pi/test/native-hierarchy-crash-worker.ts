import { join } from "node:path";
import { fauxAssistantMessage, fauxProvider, fauxToolCall } from "@earendil-works/pi-ai";
import { ModelRuntime } from "@earendil-works/pi-coding-agent";
import { AcceptanceJournal, type InstanceBinding } from "../src/adapter.js";
import { createNativePiSession } from "../src/native.js";
import { NavigatorToolBridge } from "../src/tools.js";
import { create, toBinary } from "@bufbuild/protobuf";
import { DriverEventSchema, HierarchyCommandSchema, HierarchyResultRequestSchema, InstanceIdentitySchema, SpawnChildCommandSchema, SpawnChildResultSchema } from "@navigator/driver-protocol/gen/navigator/driver/v1/driver_pb.js";

const directory = process.argv[2];
if (directory === undefined) process.exit(64);
const binding: InstanceBinding = {
  driverId: "01".repeat(16), sessionId: "02".repeat(16), participantId: "03".repeat(16),
  launchAttemptId: "04".repeat(16), instanceId: "05".repeat(16), ownershipEpoch: 7n,
};
const requestId = "31".repeat(16);
const journal = await AcceptanceJournal.open(join(directory, "journal"), binding);
const instance = create(InstanceIdentitySchema, { driverId: Buffer.from(binding.driverId, "hex"), sessionId: Buffer.from(binding.sessionId, "hex"), participantId: Buffer.from(binding.participantId, "hex"), launchAttemptId: Buffer.from(binding.launchAttemptId, "hex"), instanceId: Buffer.from(binding.instanceId, "hex"), ownershipEpoch: binding.ownershipEpoch });
const commandEvent = create(DriverEventSchema, { eventId: Buffer.alloc(16, 9), instance, sequence: 1n, inReplyTo: Buffer.alloc(16, 8), event: { case: "hierarchyCommand", value: create(HierarchyCommandSchema, { requestId: Buffer.from(requestId, "hex"), command: { case: "spawnChild", value: create(SpawnChildCommandSchema, { templateId: Buffer.alloc(16, 7) }) } }) } });
const commandSemantic = Buffer.from(toBinary(DriverEventSchema, commandEvent)).toString("base64");
const resultRequest = create(HierarchyResultRequestSchema, { instance, hierarchyRequestId: Buffer.from(requestId, "hex"), result: { case: "spawned", value: create(SpawnChildResultSchema, { participantId: Buffer.alloc(16, 6), operationId: Buffer.alloc(16, 5), inputMessageId: Buffer.alloc(16, 4) }) } });
const resultSemantic = Buffer.from(toBinary(HierarchyResultRequestSchema, resultRequest)).toString("base64");
journal.appendEvent(1n, commandSemantic);
const faux = fauxProvider({ tokensPerSecond: 1_000 });
const runtime = await ModelRuntime.create({ modelsPath: null, allowModelNetwork: false, refreshOnCreate: false });
runtime.registerNativeProvider(faux.provider);
const bridge = new NavigatorToolBridge(async () => undefined, async () => {
  journal.recordHierarchyResult(requestId, commandSemantic, resultSemantic);
  process.exit(83);
});
const session = await createNativePiSession({
  cwd: directory, sessionFile: join(directory, "session.jsonl"), baseInstructions: "Spawn.", tools: [],
}, runtime, faux.getModel(), bridge);
bridge.setActive(true);
faux.setResponses([
  fauxAssistantMessage(fauxToolCall("navigator_spawn_child", {
    request_id: requestId, template_id: "32".repeat(16), task_input_base64: "e30=",
  }), { stopReason: "toolUse" }),
]);
await session.prompt("spawn");
process.exit(65);
