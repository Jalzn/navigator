import { AcceptanceJournal, type InstanceBinding } from "../src/adapter.js";

const [path, point] = process.argv.slice(2);
if (path === undefined || (point !== "before_fsync" && point !== "after_fsync")) process.exit(64);
const binding: InstanceBinding = {
  driverId: "01".repeat(16), sessionId: "02".repeat(16), participantId: "03".repeat(16),
  launchAttemptId: "04".repeat(16), instanceId: "05".repeat(16), ownershipEpoch: 7n,
};
const journal = await AcceptanceJournal.open(path, binding, (reached) => {
  if (reached === point) process.exit(point === "before_fsync" ? 81 : 82);
});
journal.appendEvent(1n, "stable-hierarchy-command");
process.exit(0);
