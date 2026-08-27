import { appendFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import { AcceptanceJournal, type InstanceBinding } from "../src/adapter.js";

const [path, winners] = process.argv.slice(2);
if (path === undefined || winners === undefined) process.exit(64);
const binding: InstanceBinding = {
  driverId: "01".repeat(16), sessionId: "02".repeat(16), participantId: "03".repeat(16),
  launchAttemptId: "04".repeat(16), instanceId: "05".repeat(16), ownershipEpoch: 7n,
};
try {
  const journal = await AcceptanceJournal.open(path, binding);
  appendFileSync(winners, `${process.pid}\n`);
  await delay(250);
  journal.close();
  process.exit(0);
} catch {
  process.exit(75);
}
