import assert from "node:assert/strict";
import { chmodSync, linkSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { AppendOnlyObserver, MAX_OBSERVER_RECORDS } from "../src/observer.js";

test("observer rejects traversal, symlink, FIFO, hardlink, and unsafe mode", async () => {
  const root = await mkdtemp(join(tmpdir(), "navigator-observer-"));
  chmodSync(root, 0o700);
  assert.throws(() => AppendOnlyObserver.open(root, "../escape"), /basename/);
  writeFileSync(join(root, "target"), "", { mode: 0o600 });
  symlinkSync("target", join(root, "symlink"));
  assert.throws(() => AppendOnlyObserver.open(root, "symlink"));
  assert.equal(spawnSync("mkfifo", [join(root, "fifo")]).status, 0);
  assert.throws(() => AppendOnlyObserver.open(root, "fifo"));
  linkSync(join(root, "target"), join(root, "hardlink"));
  assert.throws(() => AppendOnlyObserver.open(root, "hardlink"), /unsafe/);
  writeFileSync(join(root, "mode"), "", { mode: 0o600 }); chmodSync(join(root, "mode"), 0o644);
  assert.throws(() => AppendOnlyObserver.open(root, "mode"), /unsafe/);
});

test("observer is append-only and stops at its strict record cap", async () => {
  const root = await mkdtemp(join(tmpdir(), "navigator-observer-cap-")); chmodSync(root, 0o700);
  const observer = AppendOnlyObserver.open(root, "events");
  for (let index = 0; index < MAX_OBSERVER_RECORDS + 10; index += 1) observer.append("x");
  observer.close();
  assert.equal(readFileSync(join(root, "events"), "utf8").split("\n").filter(Boolean).length, MAX_OBSERVER_RECORDS);
});
