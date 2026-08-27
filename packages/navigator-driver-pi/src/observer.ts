import { closeSync, constants, fstatSync, fsyncSync, openSync, writeSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";

export const MAX_OBSERVER_RECORDS = 512;
export const MAX_OBSERVER_BYTES = MAX_OBSERVER_RECORDS * 65;

export class AppendOnlyObserver {
  readonly #fd: number;
  #records = 0;
  #bytes = 0;
  #closed = false;
  private constructor(fd: number) { this.#fd = fd; }

  static open(privateRoot: string, configured: string): AppendOnlyObserver {
    const root = resolve(privateRoot);
    if (configured !== basename(configured) || configured.length === 0) throw new Error("observer must be a basename");
    const path = resolve(root, configured);
    if (dirname(path) !== root) throw new Error("observer must be a direct child of private runtime root");
    const fd = openSync(path, constants.O_CREAT | constants.O_APPEND | constants.O_WRONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o600);
    try {
      const stat = fstatSync(fd);
      const uid = process.getuid?.();
      if (!stat.isFile() || stat.nlink !== 1 || (uid !== undefined && stat.uid !== uid) || (stat.mode & 0o777) !== 0o600) throw new Error("unsafe observer file");
      return new AppendOnlyObserver(fd);
    } catch (error) { closeSync(fd); throw error; }
  }

  append(line: string): void {
    if (this.#closed || this.#records >= MAX_OBSERVER_RECORDS) return;
    const encoded = Buffer.from(`${line}\n`);
    if (this.#bytes + encoded.length > MAX_OBSERVER_BYTES) return;
    try {
      if (writeSync(this.#fd, encoded) !== encoded.length) return;
      fsyncSync(this.#fd);
      this.#records += 1;
      this.#bytes += encoded.length;
    } catch { /* Observation cannot alter execution. */ }
  }

  close(): void { if (!this.#closed) { this.#closed = true; closeSync(this.#fd); } }
}
