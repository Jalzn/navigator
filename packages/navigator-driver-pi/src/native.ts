import {
  createAgentSession,
  createExtensionRuntime,
  type ModelRuntime,
  type ResourceLoader,
  SessionManager,
  SettingsManager,
} from "@earendil-works/pi-coding-agent";
import type { Model } from "@earendil-works/pi-ai/compat";
import { existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname } from "node:path";
import type { PiSession } from "./adapter.js";
import type { NavigatorToolBridge } from "./tools.js";

const TOOL_ALLOWLIST = new Set(["read", "grep", "find", "ls", "bash", "edit", "write"]);

export type TrustedPiConfiguration = Readonly<{
  cwd: string;
  sessionFile: string;
  baseInstructions: string;
  tools: string[];
  hierarchyTools?: boolean;
}>;

export type NativePiObserver = Readonly<{
  onAbort?: () => void;
  onPrompt?: (sha256Hex: string) => void;
}>;

function isolatedResourceLoader(baseInstructions: string): ResourceLoader {
  return {
    getExtensions: () => ({ extensions: [], errors: [], runtime: createExtensionRuntime() }),
    getSkills: () => ({ skills: [], diagnostics: [] }),
    getPrompts: () => ({ prompts: [], diagnostics: [] }),
    getThemes: () => ({ themes: [], diagnostics: [] }),
    getAgentsFiles: () => ({ agentsFiles: [] }),
    getSystemPrompt: () => baseInstructions,
    getSystemPromptSource: () => undefined,
    getAppendSystemPrompt: () => [],
    getAppendSystemPromptSources: () => [],
    extendResources: () => undefined,
    reload: async () => undefined,
  };
}

export function validateTrustedConfiguration(value: TrustedPiConfiguration): void {
  if (value.cwd.length === 0 || value.sessionFile.length === 0 || value.baseInstructions.length === 0) {
    throw new Error("trusted Pi configuration is incomplete");
  }
  if (Buffer.byteLength(value.baseInstructions) > 64 * 1024) {
    throw new Error("base instructions exceed bound");
  }
  if (value.tools.length > TOOL_ALLOWLIST.size || value.tools.some((tool) => !TOOL_ALLOWLIST.has(tool))) {
    throw new Error("trusted Pi tool is not allowlisted");
  }
  if (value.hierarchyTools !== undefined && typeof value.hierarchyTools !== "boolean") {
    throw new Error("trusted Pi hierarchy tool selection is invalid");
  }
}

export async function createNativePiSession(
  configuration: TrustedPiConfiguration,
  modelRuntime: ModelRuntime,
  model: Model<any>,
  bridge?: NavigatorToolBridge,
  observer?: NativePiObserver,
): Promise<PiSession> {
  validateTrustedConfiguration(configuration);
  const resourceLoader = isolatedResourceLoader(configuration.baseInstructions);
  await resourceLoader.reload();
  const sessionManager = existsSync(configuration.sessionFile)
    ? SessionManager.open(configuration.sessionFile, undefined, configuration.cwd)
    : SessionManager.create(configuration.cwd, dirname(configuration.sessionFile));
  if (!existsSync(configuration.sessionFile)) {
    sessionManager.setSessionFile(configuration.sessionFile);
  }
  if (sessionManager.getSessionFile() !== configuration.sessionFile) {
    throw new Error("Pi session path binding mismatch");
  }
  const settingsManager = SettingsManager.inMemory({
    compaction: { enabled: false },
    retry: { enabled: false },
  });
  const navigatorTools = bridge?.tools(configuration.hierarchyTools !== false) ?? [];
  const activeToolNames = [...configuration.tools, ...navigatorTools.map((tool) => tool.name)];
  if (new Set(activeToolNames).size !== activeToolNames.length) {
    throw new Error("Navigator Tool name collides with configured Pi built-in");
  }
  const { session } = await createAgentSession({
    cwd: configuration.cwd,
    modelRuntime,
    model,
    tools: activeToolNames,
    resourceLoader,
    sessionManager,
    settingsManager,
    ...(navigatorTools.length === 0 ? {} : { customTools: navigatorTools }),
  });
  const active = new Set(session.getActiveToolNames());
  if (navigatorTools.some((tool) => !active.has(tool.name))) {
    throw new Error("Navigator tool activation mismatch");
  }
  return {
    sessionFile: (session as unknown as { sessionFile?: string }).sessionFile,
    prompt: async (text) => {
      observer?.onPrompt?.(createHash("sha256").update(text).digest("hex"));
      await session.prompt(text);
    },
    steer: (text) => session.steer(text),
    abort: async () => { observer?.onAbort?.(); await session.abort(); },
    dispose: () => session.dispose(),
    subscribe: (listener) => session.subscribe(listener),
    lastAssistantText: () => {
      const message = [...session.messages].reverse().find((item) => item.role === "assistant") as
        | { role: "assistant"; content: Array<{ type: string; text?: string }> }
        | undefined;
      return message?.content.filter((item) => item.type === "text").map((item) => item.text ?? "").join("\n") ?? "";
    },
  } as PiSession & { sessionFile?: string };
}

export const PROVEN_PI_CAPABILITIES = Object.freeze([
  "durable.acceptance",
]);
