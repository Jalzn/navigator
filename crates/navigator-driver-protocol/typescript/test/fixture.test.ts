import { readFileSync } from "node:fs";
import { fromBinary, toBinary } from "@bufbuild/protobuf";
import { EnvelopeSchema } from "../gen/navigator/driver/v1/driver_pb.js";

const fixture = readFileSync(new URL("../../fixtures/start-v1.bin", import.meta.url));
const envelope = fromBinary(EnvelopeSchema, fixture);
if (envelope.body.case !== "startRequest" || envelope.body.value.ownershipEpoch !== 7n) {
  throw new Error("golden StartRequest did not decode semantically");
}
if (!Buffer.from(toBinary(EnvelopeSchema, envelope)).equals(fixture)) {
  throw new Error("golden StartRequest did not round-trip");
}
