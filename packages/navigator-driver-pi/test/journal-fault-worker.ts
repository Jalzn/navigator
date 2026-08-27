import { JournalFaultController, type JournalFaultPoint } from "../src/journal-fault.js";
import { AcceptanceJournal } from "../src/adapter.js";

const controller = JournalFaultController.fromFd(Number(process.argv[2]));
const binding = { driverId: "01".repeat(16), sessionId: "02".repeat(16), participantId: "03".repeat(16), launchAttemptId: "04".repeat(16), instanceId: "05".repeat(16), ownershipEpoch: 1n };
const journal = await AcceptanceJournal.open(process.argv[3]!, binding, undefined, controller);
journal.commitPending({ messageId: "11".repeat(16), deliveryAttemptId: "12".repeat(16), operationId: "13".repeat(16), canonicalPayload: "digest-only", causeEnvelopeId: "14".repeat(16) });
journal.close();
process.exit(0);
