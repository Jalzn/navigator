import assert from "node:assert/strict";
import { PassThrough, Writable } from "node:stream";
import test from "node:test";
import { MAX_FRAME_BYTES } from "../src/adapter.js";
import { BoundedFrameReader, writeFrame } from "../src/framing.js";

test("bounded frame codec preserves adjacent frames and rejects hostile lengths", async () => {
  const stream = new PassThrough();
  const reader = new BoundedFrameReader(stream);
  await writeFrame(stream, Buffer.from("first"));
  await writeFrame(stream, Buffer.from("second"));
  assert.equal(Buffer.from((await reader.read())!).toString(), "first");
  assert.equal(Buffer.from((await reader.read())!).toString(), "second");

  const hostile = new PassThrough();
  hostile.end(Buffer.from([0x81, 0x80, 0x40]));
  await assert.rejects(new BoundedFrameReader(hostile).read(), /frame bound/);
});

test("frame reader handles fragmented long streams without listener accumulation", async () => {
  const stream = new PassThrough();
  const reader = new BoundedFrameReader(stream);
  const expected = Array.from({ length: 256 }, (_, index) => `frame-${index}`);
  for (const value of expected) {
    const payload = Buffer.from(value);
    const header = payload.length < 128
      ? Buffer.of(payload.length)
      : Buffer.of((payload.length & 0x7f) | 0x80, payload.length >> 7);
    for (const byte of Buffer.concat([header, payload])) stream.write(Buffer.of(byte));
  }
  stream.end();
  for (const value of expected) {
    assert.equal(Buffer.from((await reader.read())!).toString(), value);
  }
  assert.equal(await reader.read(), null);
});

test("frame reader rejects noncanonical and truncated varints", async () => {
  const noncanonical = new PassThrough();
  noncanonical.end(Buffer.from([0x81, 0x00, 0x41]));
  await assert.rejects(new BoundedFrameReader(noncanonical).read(), /noncanonical/);
  const truncated = new PassThrough();
  truncated.end(Buffer.from([0x80]));
  await assert.rejects(new BoundedFrameReader(truncated).read(), /truncated frame header/);
});

test("frame writer rejects a closed stream while waiting for backpressure", async () => {
  const stream = new Writable({
    highWaterMark: 1,
    write(_chunk, _encoding, callback) {
      setImmediate(callback);
    },
  });
  const write = writeFrame(stream, Buffer.alloc(128));
  stream.destroy();
  await assert.rejects(write, /closed|destroyed|premature/i);
});

test("frame reader rejects an unbounded pipelined remainder", async () => {
  const stream = new PassThrough();
  const reader = new BoundedFrameReader(stream);
  stream.end(Buffer.concat([Buffer.from([1, 65]), Buffer.alloc(1024 * 1024 + 4)]));
  await assert.rejects(reader.read(), /buffered frame data exceeds bound/);
});
