import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

test("dedicated ownership watcher survives repeated GC until the owning fd closes", async () => {
  const worker = fileURLToPath(new URL("./ownership-gc-worker.ts", import.meta.url));
  const child = spawn(process.execPath, ["--expose-gc", "--import", "tsx", worker], {
    stdio: ["ignore", "pipe", "pipe", "pipe"],
  });
  let output = "";
  assert.ok(child.stdout);
  child.stdout.on("data", (chunk: Buffer) => { output += chunk.toString(); });
  await new Promise<void>((resolve, reject) => {
    const deadline = setTimeout(() => reject(new Error(`GC worker did not survive: ${output}`)), 10_000);
    const inspect = (): void => {
      if (output.includes("survived-gc")) { clearTimeout(deadline); resolve(); }
      else if (child.exitCode !== null) { clearTimeout(deadline); reject(new Error(`ownership watcher exited early: ${child.exitCode}`)); }
      else setImmediate(inspect);
    };
    inspect();
  });
  assert.equal(child.exitCode, null);
  const ownership = child.stdio[3];
  assert.ok(ownership && "end" in ownership);
  ownership.end();
  const code = await new Promise<number | null>((resolve) => child.once("exit", resolve));
  assert.equal(code, 0);
});
