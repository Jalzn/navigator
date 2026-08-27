import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const harness = fileURLToPath(new URL("./journal-fault-harness.py", import.meta.url));

for (const scenario of ["before", "after", "mismatch", "malformed", "noncanonical", "duplicate", "trailing", "timeout"] as const) {
  test(`journal fault protocol ${scenario}`, () => {
    const result = spawnSync("python3", [harness, scenario], { timeout: 10_000 });
    assert.equal(result.status, 0, result.stderr.toString());
  });
}
