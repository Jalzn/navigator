import assert from "node:assert/strict";
import test from "node:test";
import { TerminalLineQueue } from "../src/terminal.js";

test("terminal queue survives a rejected line and drains accepted work before shutdown", async () => {
  const queue = new TerminalLineQueue();
  const events: string[] = [];
  queue.enqueue(async () => { events.push("bad"); throw new Error("bad line"); }, () => events.push("reported"));
  queue.enqueue(async () => { events.push("good"); }, () => assert.fail("valid line failed"));
  assert.equal(await queue.closeAndDrain(1_000), true);
  assert.deepEqual(events, ["bad", "reported", "good"]);
  queue.enqueue(async () => { events.push("late"); }, () => undefined);
  assert.doesNotMatch(events.join(","), /late/);
});

test("terminal drain is bounded", async () => {
  const queue = new TerminalLineQueue();
  queue.enqueue(() => new Promise<void>(() => undefined), () => undefined);
  assert.equal(await queue.closeAndDrain(5), false);
});
