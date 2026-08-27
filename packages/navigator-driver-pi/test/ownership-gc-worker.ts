import { watchDedicatedOwnershipFd } from "../src/ownership.js";

const lost = watchDedicatedOwnershipFd(3);
for (let cycle = 0; cycle < 200; cycle += 1) {
  global.gc?.();
  await new Promise((resolve) => setImmediate(resolve));
}
process.stdout.write("survived-gc\n");
await lost;
process.exit(0);
