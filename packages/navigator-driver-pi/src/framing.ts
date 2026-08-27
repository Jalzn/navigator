import type { Readable, Writable } from "node:stream";
import { MAX_FRAME_BYTES } from "./adapter.js";

export class BoundedFrameReader {
  readonly #iterator: AsyncIterator<unknown>;
  #buffer = Buffer.alloc(0);

  constructor(stream: Readable) {
    this.#iterator = stream[Symbol.asyncIterator]();
  }

  #append(chunk: Buffer): void {
    // The protocol is request/response, not pipelined. Bounding aggregate
    // unread bytes prevents a peer from hiding an unbounded tail behind one
    // otherwise-valid frame.
    if (this.#buffer.length + chunk.length > MAX_FRAME_BYTES + 5) {
      throw new Error("buffered frame data exceeds bound");
    }
    this.#buffer = Buffer.concat([this.#buffer, chunk]);
  }

  async #chunk(): Promise<Buffer | null> {
    const next = await this.#iterator.next();
    if (next.done === true) return null;
    if (!(next.value instanceof Uint8Array)) throw new Error("invalid stream chunk");
    return Buffer.from(next.value);
  }

  async read(): Promise<Uint8Array | null> {
    let size = 0;
    let shift = 0;
    let headerBytes = 0;
    for (;;) {
      while (this.#buffer.length <= headerBytes) {
        const chunk = await this.#chunk();
        if (chunk === null) {
          if (headerBytes !== 0 || this.#buffer.length !== 0) throw new Error("truncated frame header");
          return null;
        }
        this.#append(chunk);
      }
      const byte = this.#buffer[headerBytes]!;
      headerBytes += 1;
      if (headerBytes > 5) throw new Error("overlong frame length");
      size += (byte & 0x7f) * (2 ** shift);
      if ((byte & 0x80) === 0) {
        if (headerBytes > 1 && byte === 0) throw new Error("noncanonical frame length");
        break;
      }
      shift += 7;
    }
    if (size === 0 || size > MAX_FRAME_BYTES) throw new Error("invalid frame bound");
    while (this.#buffer.length < headerBytes + size) {
      const chunk = await this.#chunk();
      if (chunk === null) throw new Error("truncated frame payload");
      this.#append(chunk);
    }
    const frame = this.#buffer.subarray(headerBytes, headerBytes + size);
    this.#buffer = this.#buffer.subarray(headerBytes + size);
    return frame;
  }
}

function lengthVarint(value: number): Buffer {
  const bytes: number[] = [];
  let remaining = value;
  do {
    let byte = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
    if (remaining !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (remaining !== 0);
  return Buffer.from(bytes);
}

export async function writeFrame(stream: Writable, payload: Uint8Array): Promise<void> {
  if (payload.length === 0 || payload.length > MAX_FRAME_BYTES) throw new Error("invalid frame bound");
  if (stream.write(Buffer.concat([lengthVarint(payload.length), payload]))) return;
  await new Promise<void>((resolve, reject) => {
    const cleanup = (): void => {
      stream.off("drain", drained);
      stream.off("error", failed);
      stream.off("close", closed);
    };
    const drained = (): void => { cleanup(); resolve(); };
    const failed = (error: Error): void => { cleanup(); reject(error); };
    const closed = (): void => { cleanup(); reject(new Error("frame stream closed")); };
    stream.once("drain", drained);
    stream.once("error", failed);
    stream.once("close", closed);
  });
}
