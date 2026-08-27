import { Worker } from "node:worker_threads";

export function watchDedicatedOwnershipFd(ownershipFd: number): Promise<void> {
  if (!Number.isSafeInteger(ownershipFd) || ownershipFd <= 0) throw new Error("invalid dedicated ownership fd");
  const watcher = new Worker(`
    const { readSync } = require("node:fs");
    const { parentPort, workerData } = require("node:worker_threads");
    try { readSync(workerData, Buffer.alloc(1), 0, 1, null); } catch (_) {}
    parentPort.postMessage("lost");
  `, { eval: true, workerData: ownershipFd });
  const lost = new Promise<void>((resolve) => {
    watcher.once("message", resolve);
    watcher.once("error", resolve);
    watcher.once("exit", resolve);
  });
  // The finally closure deliberately retains the Worker strongly until one of
  // its terminal signals settles ownership loss.
  return lost.finally(() => watcher.removeAllListeners());
}
