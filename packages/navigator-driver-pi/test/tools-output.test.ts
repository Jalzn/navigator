import assert from "node:assert/strict";
import test from "node:test";
import { decodeToolOutput, NavigatorToolBridge, type ToolArtifactResult } from "../src/tools.js";

const registrationId = Buffer.alloc(16, 7);
const context = {
  operationId: Buffer.alloc(16, 1),
  messageId: Buffer.alloc(16, 2),
  deliveryAttemptId: Buffer.alloc(16, 3),
  inReplyTo: Buffer.alloc(16, 4),
};

const artifacts: readonly ToolArtifactResult[] = [{
  artifactId: "08".repeat(16),
  sessionId: "09".repeat(16),
  creatorParticipantId: "0a".repeat(16),
  creatorOperationId: "0b".repeat(16),
  mediaType: "application/json",
  size: "31",
  sha256: "0c".repeat(32),
}];

function registeredTool(outputBase64: string) {
  const bridge = new NavigatorToolBridge(
    async () => undefined,
    undefined,
    undefined,
    undefined,
    undefined,
    async () => ({ outputBase64, artifacts }),
  );
  bridge.configureToolCatalog([{
    registrationId,
    name: "Records.Lookup",
    version: "V1",
    inputSchema: { type: "object", additionalProperties: false },
  }]);
  bridge.setActive(true, context);
  const tool = bridge.tools().find((candidate) => candidate.name === `navigator_registered_tool_${registrationId.toString("hex")}`);
  assert(tool !== undefined);
  return tool.execute as (...arguments_: unknown[]) => Promise<{
    content: Array<{ type: string; text?: string }>;
    details: { artifacts: readonly ToolArtifactResult[] };
  }>;
}

test("registered Tool exposes decoded UTF-8 JSON and preserves artifacts", async () => {
  const output = JSON.stringify({ ok: true, mensagem: "ação concluída ✓" });
  const observed = await registeredTool(Buffer.from(output, "utf8").toString("base64"))("call-1", {});

  assert.equal(observed.content[0]?.text, output);
  assert.deepEqual(observed.details, { artifacts });
});

test("registered Tool exposes decoded ASCII JSON exactly", async () => {
  const output = '{"ok":true,"value":42}';
  const observed = await registeredTool(Buffer.from(output, "utf8").toString("base64"))("call-ascii", {});

  assert.equal(observed.content[0]?.text, output);
  assert.deepEqual(observed.details, { artifacts });
});

test("registered Tool rejects malformed outputBase64 explicitly", async () => {
  await assert.rejects(
    registeredTool("not base64")("call-2", {}),
    /invalid outputBase64/,
  );
});

for (const nonCanonical of ["", "Zh==", "AB=="]) {
  test(`registered Tool rejects non-canonical outputBase64 ${JSON.stringify(nonCanonical)}`, async () => {
    await assert.rejects(
      registeredTool(nonCanonical)("call-non-canonical", {}),
      /non-canonical outputBase64/,
    );
  });
}

test("registered Tool rejects decoded bytes that are not UTF-8 explicitly", async () => {
  const invalidUtf8 = Buffer.from([0xc3, 0x28]).toString("base64");
  await assert.rejects(
    registeredTool(invalidUtf8)("call-3", {}),
    /not valid UTF-8/,
  );
});

test("output decoder preserves exact JSON text without parsing or reserializing it", () => {
  const output = '{ "nested": { "value": 1 }, "items": [1, 2] }';
  assert.equal(decodeToolOutput(Buffer.from(output).toString("base64")), output);
});
