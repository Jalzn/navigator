#!/usr/bin/env node
import { chmodSync, lstatSync, readFileSync, unlinkSync } from "node:fs";
import { createServer, Socket } from "node:net";
import { join, resolve } from "node:path";
import { ModelRuntime } from "@earendil-works/pi-coding-agent";
import { AcceptanceJournal, captureCredential, PiAdapter } from "./adapter.js";
import { BoundedFrameReader, writeFrame } from "./framing.js";
import { createNativePiSession, PROVEN_PI_CAPABILITIES, type TrustedPiConfiguration } from "./native.js";
import { PiDriverServer } from "./server.js";
import { watchDedicatedOwnershipFd } from "./ownership.js";
import { TerminalLineQueue } from "./terminal.js";
import { AppendOnlyObserver } from "./observer.js";
import { JournalFaultController } from "./journal-fault.js";

type RuntimeConfiguration = Readonly<{
  provider: string;
  model: string;
  authPath: string;
  modelsPath?: string;
  providerModule?: string;
  terminalMode?: "line";
  cwd: string;
  tools: string[];
  abortObserverPath?: string;
  promptObserverPath?: string;
  deliveryObserverPath?: string;
  journalFaultFd?: number;
}>;

type NavigatorTrustedConfiguration = Readonly<{
  base_instructions: string;
  secret_names: string[];
  navigator_tool_catalog: unknown[];
}>;

function required(name: string): string {
  const value = process.env[name];
  delete process.env[name];
  if (value === undefined || value.length === 0) throw new Error(`missing ${name}`);
  return value;
}

function exactId(name: string): Buffer {
  const encoded = required(name);
  if (!/^[0-9a-fA-F]{32}$/.test(encoded)) throw new Error(`invalid ${name}`);
  const value = Buffer.from(encoded, "hex");
  if (value.length !== 16 || value.every((byte) => byte === 0)) throw new Error(`invalid ${name}`);
  return value;
}

function dispatchFailure(error: unknown): string {
  const message = error instanceof Error ? error.message : "";
  if (message.includes("authentication") || message.includes("credential")) return "authentication";
  if (message.includes("identity") || message.includes("binding")) return "identity";
  if (message.includes("capacity")) return "capacity";
  if (message.includes("stopped") || message.includes("ownership")) return "stopped";
  return "internal";
}

async function serveConnection(socket: Socket, dispatcher: PiDriverServer): Promise<void> {
  const reader = new BoundedFrameReader(socket);
  for (;;) {
    const frame = await reader.read();
    if (frame === null) return;
    let response: Uint8Array;
    try {
      response = await dispatcher.handle(frame);
    } catch (error) {
      process.stderr.write(`navigator.pi.connection.dispatch:${dispatchFailure(error)}\n`);
      throw error;
    }
    try {
      await writeFrame(socket, response);
    } catch (error) {
      process.stderr.write("navigator.pi.connection.write_failed\n");
      throw error;
    }
  };
}

async function main(): Promise<void> {
  process.umask(0o077);
  const controlSocket = required("NAVIGATOR_CONTROL_SOCKET");
  const ownershipFdText = process.env.NAVIGATOR_OWNERSHIP_FD ?? "0";
  delete process.env.NAVIGATOR_OWNERSHIP_FD;
  const ownershipFd = Number(ownershipFdText);
  if (!Number.isSafeInteger(ownershipFd) || ownershipFd < 0) throw new Error("invalid ownership fd");
  const ownershipLost = ownershipFd === 0
    ? new Promise<void>((resolve) => {
        process.stdin.once("data", () => resolve());
        process.stdin.once("end", resolve);
        process.stdin.once("error", () => resolve());
        process.stdin.once("close", resolve);
        process.stdin.resume();
      })
    : watchDedicatedOwnershipFd(ownershipFd);
  const driverId = exactId("NAVIGATOR_DRIVER_ID");
  const secret = captureCredential(process.env);
  const bootstrapPath = required("NAVIGATOR_DRIVER_BOOTSTRAP_FILE");
  const bootstrapMetadata = lstatSync(bootstrapPath);
  if (!bootstrapMetadata.isFile() || bootstrapMetadata.isSymbolicLink() || (bootstrapMetadata.mode & 0o077) !== 0) {
    throw new Error("Driver bootstrap file is unsafe");
  }
  const runtimeConfiguration = JSON.parse(readFileSync(bootstrapPath, "utf8")) as RuntimeConfiguration;
  unlinkSync(bootstrapPath);
  const runtimeRoot = resolve(required("NAVIGATOR_DRIVER_PRIVATE_ROOT"));
  const runtimeRootMetadata = lstatSync(runtimeRoot);
  if (!runtimeRootMetadata.isDirectory() || runtimeRootMetadata.isSymbolicLink() || (runtimeRootMetadata.mode & 0o077) !== 0) {
    throw new Error("private runtime root is unsafe");
  }
  const observer = (name: "abortObserverPath" | "promptObserverPath" | "deliveryObserverPath"): AppendOnlyObserver | undefined => {
    const configured = runtimeConfiguration[name];
    if (configured === undefined) return undefined;
    return AppendOnlyObserver.open(runtimeRoot, configured);
  };
  const abortObserver = observer("abortObserverPath");
  const promptObserver = observer("promptObserverPath");
  const deliveryObserver = observer("deliveryObserverPath");
  if (runtimeConfiguration.journalFaultFd !== undefined && runtimeConfiguration.journalFaultFd === ownershipFd) {
    throw new Error("journal fault fd collides with ownership fd");
  }
  const journalFault = runtimeConfiguration.journalFaultFd === undefined
    ? undefined
    : JournalFaultController.fromFd(runtimeConfiguration.journalFaultFd);
  if (runtimeConfiguration.terminalMode === "line" && (ownershipFd === 0 || process.stdin.isTTY !== true)) {
    throw new Error("line terminal requires a TTY on stdin and separate ownership fd");
  }
  const runtime = await ModelRuntime.create({
    authPath: runtimeConfiguration.authPath,
    modelsPath: runtimeConfiguration.modelsPath ?? null,
    allowModelNetwork: false,
    refreshOnCreate: false,
  });
  if (runtimeConfiguration.providerModule !== undefined) {
    const loaded = await import(runtimeConfiguration.providerModule) as {
      register?: (runtime: ModelRuntime) => void | Promise<void>;
    };
    if (loaded.register === undefined) throw new Error("Pi provider module lacks register()");
    await loaded.register(runtime);
  }
  const model = runtime.getModel(runtimeConfiguration.provider, runtimeConfiguration.model);
  if (model === undefined) throw new Error("trusted Pi model is unavailable");
  const dispatcher = new PiDriverServer(secret, driverId, async (binding, trustedBytes, bridge) => {
    const trusted = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(trustedBytes)) as NavigatorTrustedConfiguration;
    if (typeof trusted.base_instructions !== "string" || !Array.isArray(trusted.secret_names) || trusted.secret_names.length !== 0) {
      throw new Error("unsupported trusted configuration");
    }
    if (Object.keys(trusted).some((key) => !["base_instructions", "secret_names", "navigator_tool_catalog"].includes(key))) {
      throw new Error("unknown trusted configuration field");
    }
    const sessionFile = join(runtimeRoot, `${binding.participantId}-${binding.launchAttemptId}-${binding.instanceId}.jsonl`);
    const configuration: TrustedPiConfiguration = {
      cwd: runtimeConfiguration.cwd,
      sessionFile,
      baseInstructions: trusted.base_instructions,
      tools: runtimeConfiguration.tools,
    };
    const session = await createNativePiSession(configuration, runtime, model, bridge,
      abortObserver === undefined && promptObserver === undefined ? undefined : {
        ...(abortObserver === undefined ? {} : { onAbort: () => abortObserver.append("abort") }),
        ...(promptObserver === undefined ? {} : { onPrompt: (digest: string) => promptObserver.append(digest) }),
      });
    const journal = await AcceptanceJournal.open(`${configuration.sessionFile}.navigator-inbox`, binding, undefined, journalFault);
    return new PiAdapter(binding, session, journal, bridge, deliveryObserver === undefined ? undefined : (line) => deliveryObserver.append(line));
  }, [
    ...PROVEN_PI_CAPABILITIES,
    ...(runtimeConfiguration.terminalMode === "line"
      ? [{ id: "interactive-terminal.v1", parameters: { mode: "line" } }]
      : []),
  ]);

  const terminalQueue = runtimeConfiguration.terminalMode === "line" ? new TerminalLineQueue() : undefined;
  if (terminalQueue !== undefined) {
    let pending = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk: string) => {
      pending += chunk;
      if (Buffer.byteLength(pending) > 64 * 1024) process.exit(64);
      for (;;) {
        const newline = pending.indexOf("\n");
        if (newline < 0) break;
        const line = pending.slice(0, newline).replace(/\r$/, "");
        pending = pending.slice(newline + 1);
        terminalQueue.enqueue(async () => {
          await dispatcher.interactiveLine(line);
          process.stdout.write("SETTLED\n");
        }, (error) => process.stderr.write(`navigator.pi.terminal:${dispatchFailure(error)}\n`));
      }
    });
    process.stdin.resume();
  }

  const server = createServer((socket) => {
    void serveConnection(socket, dispatcher).catch(() => socket.destroy());
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(controlSocket, resolve);
  });
  chmodSync(controlSocket, 0o600);
  const identity = lstatSync(controlSocket);
  const shutdown = async (): Promise<void> => {
    server.close();
    let cleanupTimedOut = false;
    let cleanupTimer: NodeJS.Timeout | undefined;
    try {
      const deadline = new Promise<void>((resolve) => {
        cleanupTimer = setTimeout(() => { cleanupTimedOut = true; resolve(); }, 1_000);
      });
      const cleanup = Promise.resolve().then(async () => {
        process.stdin.pause();
        // Stop terminal admission first and drain already accepted lines within
        // the shared cleanup budget before disposing the Pi session.
        if (terminalQueue !== undefined && !await terminalQueue.closeAndDrain(900)) cleanupTimedOut = true;
        await dispatcher.stop();
        abortObserver?.close();
        promptObserver?.close();
        deliveryObserver?.close();
        journalFault?.close();
      });
      await Promise.race([cleanup, deadline]);
    } finally {
      if (cleanupTimer !== undefined) clearTimeout(cleanupTimer);
    }
    try {
      const current = lstatSync(controlSocket);
      if (current.isSocket() && current.dev === identity.dev && current.ino === identity.ino) unlinkSync(controlSocket);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    process.exit(cleanupTimedOut ? 70 : 0);
  };
  await ownershipLost;
  await shutdown();
}

await main();
