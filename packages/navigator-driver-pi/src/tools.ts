import { Type } from "@earendil-works/pi-ai";
import { createHash } from "node:crypto";
import { defineTool, type ToolDefinition } from "@earendil-works/pi-coding-agent";

export type ReportKindName = "progress" | "question" | "blocked" | "succeeded" | "failed" | "cancelled" | "uncertain";
export type ReportEmission = Readonly<{ kind: ReportKindName; payload: Uint8Array }>;
export type SpawnEmission = Readonly<{
  requestId: Uint8Array;
  templateId: Uint8Array;
  taskInput: Uint8Array;
  grantId: Uint8Array;
}>;
export type SendEmission = Readonly<{ requestId: Uint8Array; destinationId: Uint8Array; envelope: Uint8Array }>;
export type StatusEmission = Readonly<{ requestId: Uint8Array; participantId: Uint8Array; operationId: Uint8Array }>;
export type CancelEmission = StatusEmission;
export type ToolEmission = Readonly<{ requestId: Uint8Array; name: string; version: string; input: Uint8Array; grantId: Uint8Array }>;
export type ToolArtifactResult = Readonly<{
  artifactId: string; sessionId: string; creatorParticipantId: string; creatorOperationId: string;
  mediaType: string; size: string; sha256: string;
}>;
export type ToolObservableResult = Readonly<{ outputBase64: string; artifacts: readonly ToolArtifactResult[] }>;
export type TrustedToolCatalogEntry = Readonly<{ registrationId: Uint8Array; name: string; version: string; inputSchema: Record<string, unknown> }>;
export type DeliveryContext = Readonly<{
  operationId: Uint8Array;
  messageId: Uint8Array;
  deliveryAttemptId: Uint8Array;
  inReplyTo: Uint8Array;
}>;

function identifier(value: string | undefined, optional = false): Uint8Array {
  if (optional && (value === undefined || value.length === 0)) return new Uint8Array();
  if (value === undefined || !/^[0-9a-fA-F]{32}$/.test(value)) throw new Error("invalid Navigator identifier");
  const decoded = Buffer.from(value, "hex");
  if (decoded.every((byte) => byte === 0)) throw new Error("invalid Navigator identifier");
  return decoded;
}

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (typeof value !== "object" || value === null) return value;
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([left], [right]) => left.localeCompare(right)).map(([key, child]) => [key, canonical(child)]));
}

export class NavigatorToolBridge {
  readonly #emitReport: (report: ReportEmission) => Promise<void>;
  readonly #spawnChild: (command: SpawnEmission) => Promise<string>;
  readonly #send: (command: SendEmission) => Promise<string>;
  readonly #status: (command: StatusEmission) => Promise<string>;
  readonly #cancel: (command: CancelEmission) => Promise<string>;
  readonly #tool: (command: ToolEmission) => Promise<ToolObservableResult>;
  #context: DeliveryContext | undefined = undefined;
  #active = false;
  #reportsAllowed = false;
  #toolCatalog: TrustedToolCatalogEntry[] = [];
  #toolCatalogConfigured = false;

  constructor(
    emitReport: (report: ReportEmission) => Promise<void>,
    spawnChild: (command: SpawnEmission) => Promise<string> = async () => { throw new Error("hierarchy unavailable"); },
    send: (command: SendEmission) => Promise<string> = async () => { throw new Error("hierarchy unavailable"); },
    status: (command: StatusEmission) => Promise<string> = async () => { throw new Error("hierarchy unavailable"); },
    cancel: (command: CancelEmission) => Promise<string> = async () => { throw new Error("hierarchy unavailable"); },
    tool: (command: ToolEmission) => Promise<ToolObservableResult> = async () => { throw new Error("tool unavailable"); },
  ) {
    this.#emitReport = emitReport;
    this.#spawnChild = spawnChild;
    this.#send = send;
    this.#status = status;
    this.#cancel = cancel;
    this.#tool = tool;
  }

  setActive(active: boolean, context?: DeliveryContext, reportsAllowed = true): void {
    this.#active = active;
    this.#context = active ? context : undefined;
    this.#reportsAllowed = active && reportsAllowed;
  }

  context(): DeliveryContext | undefined {
    return this.#context;
  }

  configureToolCatalog(entries: TrustedToolCatalogEntry[]): void {
    if (this.#toolCatalogConfigured) {
      const identity = (values: TrustedToolCatalogEntry[]) => JSON.stringify(values.map((entry) => [Buffer.from(entry.registrationId).toString("hex"), entry.name, entry.version, entry.inputSchema]));
      if (identity(this.#toolCatalog) !== identity(entries)) throw new Error("Tool catalog conflict");
      return;
    }
    this.#toolCatalog = [...entries];
    this.#toolCatalogConfigured = true;
  }

  tools(): ToolDefinition[] {
    const commandTool = defineTool({
      name: "navigator_command",
      label: "Navigator command",
      description: "Perform one typed authenticated Navigator report or hierarchy command.",
      parameters: Type.Object({
        action: Type.Union([Type.Literal("report"), Type.Literal("spawn"), Type.Literal("send"), Type.Literal("status"), Type.Literal("cancel")]),
        request_id: Type.Optional(Type.String()), kind: Type.Optional(Type.String()), payload: Type.Optional(Type.String({ maxLength: 65536 })),
        template_id: Type.Optional(Type.String()), task_input_base64: Type.Optional(Type.String({ maxLength: 1398104 })), grant_id: Type.Optional(Type.String()),
        destination_participant_id: Type.Optional(Type.String()), validated_envelope_base64: Type.Optional(Type.String({ maxLength: 1398104 })),
        participant_id: Type.Optional(Type.String()), operation_id: Type.Optional(Type.String()),
      }, { additionalProperties: false }),
      execute: async (_id, params) => {
        if (!this.#active) throw new Error("no active Navigator turn");
        if (params.action === "report" && (this.#context === undefined || !this.#reportsAllowed)) throw new Error("report requires an active Navigator delivery");
        if (params.action === "report") {
          const kinds = new Set<ReportKindName>(["progress", "question", "blocked", "succeeded", "failed", "cancelled", "uncertain"]);
          if (!kinds.has(params.kind as ReportKindName)) throw new Error("invalid report kind");
          await this.#emitReport({ kind: params.kind as ReportKindName, payload: new TextEncoder().encode(params.payload ?? "") });
          return { content: [{ type: "text" as const, text: "Navigator durably received the report." }], details: {} };
        }
        const requestId = identifier(params.request_id);
        let result: string;
        if (params.action === "spawn") result = await this.#spawnChild({ requestId, templateId: identifier(params.template_id), taskInput: Buffer.from(params.task_input_base64 ?? "", "base64"), grantId: identifier(params.grant_id, true) });
        else if (params.action === "send") result = await this.#send({ requestId, destinationId: identifier(params.destination_participant_id), envelope: Buffer.from(params.validated_envelope_base64 ?? "", "base64") });
        else {
          const command = { requestId, participantId: identifier(params.participant_id), operationId: identifier(params.operation_id) };
          result = await (params.action === "status" ? this.#status(command) : this.#cancel(command));
        }
        return { content: [{ type: "text" as const, text: result }], details: {} };
      },
    });
    const tools = [defineTool({
      name: "navigator_report",
      label: "Navigator report",
      description: "Report bounded progress, a question, or a terminal operation outcome to Navigator.",
      parameters: Type.Object({
        kind: Type.Union([
          Type.Literal("progress"), Type.Literal("question"), Type.Literal("blocked"),
          Type.Literal("succeeded"), Type.Literal("failed"), Type.Literal("cancelled"),
          Type.Literal("uncertain"),
        ]),
        payload: Type.String({ maxLength: 65536 }),
      }),
      execute: async (_toolCallId, params) => {
        if (this.#context === undefined || !this.#reportsAllowed) throw new Error("report requires an active Navigator delivery");
        const payload = new TextEncoder().encode(params.payload);
        if (payload.length > 65536) throw new Error("Navigator report exceeds bound");
        await this.#emitReport({ kind: params.kind, payload });
        return { content: [{ type: "text", text: "Navigator durably received the report." }], details: {} };
      },
    }), defineTool({
      name: "navigator_spawn_child",
      label: "Spawn Navigator child",
      description: "Atomically create an authorized direct child and its first operation.",
      parameters: Type.Object({
        request_id: Type.String(),
        template_id: Type.String(),
        task_input_base64: Type.String({ maxLength: 1398104 }),
        grant_id: Type.Optional(Type.String()),
      }),
      execute: async (_toolCallId, params) => {
        if (!this.#active) throw new Error("no active Navigator turn");
        const taskInput = Buffer.from(params.task_input_base64, "base64");
        if (taskInput.length > 1024 * 1024) throw new Error("child task input exceeds bound");
        const result = await this.#spawnChild({
          requestId: identifier(params.request_id),
          templateId: identifier(params.template_id),
          taskInput,
          grantId: identifier(params.grant_id, true),
        });
        return { content: [{ type: "text", text: result }], details: {} };
      },
    }), defineTool({
      name: "navigator_send_message", label: "Send Navigator message",
      description: "Send a validated bounded envelope through Navigator topology policy.",
      parameters: Type.Object({ request_id: Type.String(), destination_participant_id: Type.String(), validated_envelope_base64: Type.String({ maxLength: 1398104 }) }),
      execute: async (_id, params) => {
        if (!this.#active) throw new Error("no active Navigator turn");
        const envelope = Buffer.from(params.validated_envelope_base64, "base64");
        if (envelope.length > 1024 * 1024) throw new Error("message envelope exceeds bound");
        const result = await this.#send({ requestId: identifier(params.request_id), destinationId: identifier(params.destination_participant_id), envelope });
        return { content: [{ type: "text", text: result }], details: {} };
      },
    }), ...(["status", "cancel"] as const).map((action) => defineTool({
      name: `navigator_${action}_child`, label: `${action} Navigator child`,
      description: `${action} an authorized direct child operation through Navigator.`,
      parameters: Type.Object({ request_id: Type.String(), participant_id: Type.String(), operation_id: Type.String() }),
      execute: async (_id, params) => {
        if (!this.#active) throw new Error("no active Navigator turn");
        const command = { requestId: identifier(params.request_id), participantId: identifier(params.participant_id), operationId: identifier(params.operation_id) };
        const result = await (action === "status" ? this.#status(command) : this.#cancel(command));
        return { content: [{ type: "text", text: result }], details: {} };
      },
    }))];
    const registered = this.#toolCatalog.map((entry) => defineTool({
      name: `navigator_registered_tool_${Buffer.from(entry.registrationId).toString("hex")}`,
      label: entry.name,
      description: `Invoke trusted Navigator Tool ${entry.name}@${entry.version}.`,
      parameters: Type.Unsafe(entry.inputSchema),
      execute: async (toolCallId, params) => {
        if (!this.#active || this.#context === undefined) throw new Error("no active Navigator delivery");
        const requestId = createHash("sha256").update("navigator.pi.tool.request\0").update(this.#context.operationId).update(toolCallId).digest().subarray(0, 16);
        requestId[6] = (requestId[6]! & 0x0f) | 0x40; requestId[8] = (requestId[8]! & 0x3f) | 0x80;
        const input = new TextEncoder().encode(JSON.stringify(canonical(params)));
        if (input.length > 65536) throw new Error("Tool input exceeds bound");
        const result = await this.#tool({ requestId, name: entry.name, version: entry.version, input, grantId: new Uint8Array() });
        return { content: [{ type: "text", text: result.outputBase64 }], details: { artifacts: result.artifacts } };
      },
    }));
    return [commandTool, ...tools, ...registered];
  }
}
