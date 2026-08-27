import { fstatSync, readSync, writeSync } from "node:fs";
import { Socket } from "node:net";
import { performance } from "node:perf_hooks";

export type JournalFaultPoint = "before_append" | "after_fsync";
export type JournalFaultTarget = Readonly<{ messageId: string; deliveryAttemptId: string }>;

const MAX_FRAME = 512;
const WAIT_MS = 5_000;
const pause = new Int32Array(new SharedArrayBuffer(4));

function exactId(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{32}$/.test(value);
}

/** Test-only deterministic crash-window synchronization over an inherited FD. */
export class JournalFaultController {
  readonly #fd: number;
  readonly #socket: Socket;
  readonly #arm: JournalFaultTarget & { point: JournalFaultPoint };
  #reached = false;
  #closed = false;
  #input = Buffer.alloc(0);

  static fromFd(fd: number): JournalFaultController {
    if (!Number.isSafeInteger(fd) || fd < 3) throw new Error("invalid journal fault fd");
    const metadata = fstatSync(fd);
    if (!metadata.isSocket()) throw new Error("journal fault fd is not a socket");
    return new JournalFaultController(fd);
  }

  private constructor(fd: number) {
    this.#fd = fd;
    // Wrapping the inherited socket puts it into non-blocking mode, which lets
    // the bounded polling below enforce deadlines even when the parent did not.
    this.#socket = new Socket({ fd, readable: true, writable: true });
    this.#socket.pause();
    try {
      const arm = this.#readFrame(0, true);
      if (arm.type !== "ARM" || (arm.point !== "before_append" && arm.point !== "after_fsync")
        || !exactId(arm.messageId) || !exactId(arm.deliveryAttemptId)
        || Object.keys(arm).filter((key) => key !== "__raw").sort().join(",") !== "deliveryAttemptId,messageId,point,type") {
        throw new Error("malformed journal fault ARM");
      }
      const canonical = JSON.stringify({ type: "ARM", point: arm.point, messageId: arm.messageId, deliveryAttemptId: arm.deliveryAttemptId });
      if (arm.__raw !== canonical) throw new Error("noncanonical journal fault ARM");
      this.#arm = { point: arm.point, messageId: arm.messageId, deliveryAttemptId: arm.deliveryAttemptId };
    } catch (error) {
      this.close();
      throw error;
    }
  }

  reach(point: JournalFaultPoint, target: JournalFaultTarget): void {
    if (this.#reached || point !== this.#arm.point || target.messageId !== this.#arm.messageId
      || target.deliveryAttemptId !== this.#arm.deliveryAttemptId) return;
    this.#reached = true;
    try {
      this.#writeFrame({ type: "REACHED", point, messageId: target.messageId, deliveryAttemptId: target.deliveryAttemptId });
      const release = this.#readFrame(WAIT_MS);
      if (release.type !== "RELEASE" || Object.keys(release).filter((key) => key !== "__raw").join(",") !== "type") {
        throw new Error("malformed journal fault RELEASE");
      }
      if (release.__raw !== '{"type":"RELEASE"}' || this.#input.length !== 0 || this.#hasTrailingInput()) {
        throw new Error("trailing journal fault frame");
      }
    } finally {
      this.close();
    }
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#socket.destroy();
  }

  #readFrame(timeoutMs: number, preloaded = false): Record<string, unknown> {
    const deadline = performance.now() + timeoutMs;
    let attempted = false;
    for (;;) {
      const newline = this.#input.indexOf(0x0a);
      if (newline >= 0) {
        const line = this.#input.subarray(0, newline);
        this.#input = this.#input.subarray(newline + 1);
        if (line.length === 0 || line.length > MAX_FRAME) throw new Error("invalid journal fault frame length");
        const raw = line.toString("utf8");
        try { return { ...(JSON.parse(raw) as Record<string, unknown>), __raw: raw }; }
        catch { throw new Error("malformed journal fault frame"); }
      }
      if (this.#input.length > MAX_FRAME || (!preloaded && performance.now() >= deadline)) throw new Error("journal fault protocol timeout");
      const chunk = Buffer.alloc(128);
      try {
        const read = readSync(this.#fd, chunk, 0, chunk.length, null);
        attempted = true;
        if (read === 0) throw new Error("journal fault protocol EOF");
        this.#input = Buffer.concat([this.#input, chunk.subarray(0, read)]);
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code !== "EAGAIN" && code !== "EWOULDBLOCK") throw error;
        if (preloaded || attempted) throw new Error("journal fault ARM must be preloaded");
        Atomics.wait(pause, 0, 0, 2);
      }
    }
  }

  #writeFrame(value: Record<string, unknown>): void {
    const frame = Buffer.from(`${JSON.stringify(value)}\n`);
    if (frame.length > MAX_FRAME) throw new Error("journal fault response exceeds bound");
    let offset = 0;
    const deadline = performance.now() + WAIT_MS;
    while (offset < frame.length) {
      try {
        const written = writeSync(this.#fd, frame, offset, frame.length - offset);
        if (written === 0) { if (performance.now() >= deadline) throw new Error("journal fault protocol timeout"); Atomics.wait(pause, 0, 0, 2); }
        else offset += written;
      }
      catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if ((code !== "EAGAIN" && code !== "EWOULDBLOCK") || performance.now() >= deadline) throw error;
        Atomics.wait(pause, 0, 0, 2);
      }
    }
  }

  #hasTrailingInput(): boolean {
    const byte = Buffer.alloc(1);
    try { return readSync(this.#fd, byte, 0, 1, null) !== 0; }
    catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "EAGAIN" || code === "EWOULDBLOCK") return false;
      throw error;
    }
  }
}
