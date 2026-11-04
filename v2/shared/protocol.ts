import * as Schema from 'effect/Schema';

export const DrawShape = Schema.Struct({
  id: Schema.String,
  kind: Schema.Literals(['box', 'arrow', 'text', 'highlight']),
  x: Schema.Number,
  y: Schema.Number,
  w: Schema.Number,
  h: Schema.Number,
  label: Schema.optional(Schema.String),
  color: Schema.optional(Schema.String),
});
export type DrawShape = typeof DrawShape.Type;

export const McpTool = Schema.Struct({
  server: Schema.String,
  name: Schema.String,
  description: Schema.String,
  inputSchema: Schema.Unknown,
});
export type McpTool = typeof McpTool.Type;

export const McpResult = Schema.Struct({ type: Schema.Literal('mcp_result'), callId: Schema.String, ok: Schema.Boolean, text: Schema.String });

export const AgentWindow = Schema.Struct({
  id: Schema.String,
  title: Schema.String,
  html: Schema.String,
  width: Schema.Number,
  height: Schema.Number,
  updatedAt: Schema.Number,
});
export type AgentWindow = typeof AgentWindow.Type;

export const WindowClosed = Schema.Struct({ type: Schema.Literal('window_closed'), id: Schema.String });

export const TurnRequest = Schema.Struct({
  type: Schema.Literal('turn'),
  turnId: Schema.String,
  text: Schema.String,
  screen: Schema.optional(Schema.Struct({ width: Schema.Number, height: Schema.Number })),
  tools: Schema.optional(Schema.Array(McpTool)),
});
export type TurnRequest = typeof TurnRequest.Type;

export const ClientFrame = Schema.Union([TurnRequest, Schema.Struct({ type: Schema.Literal('cancel'), turnId: Schema.String }), McpResult, WindowClosed]);
export type ClientFrame = typeof ClientFrame.Type;

export const ServerFrame = Schema.Union([
  Schema.Struct({ type: Schema.Literal('text'), turnId: Schema.String, text: Schema.String }),
  Schema.Struct({ type: Schema.Literal('draw'), turnId: Schema.String, shape: DrawShape }),
  Schema.Struct({ type: Schema.Literal('clear'), turnId: Schema.String }),
  Schema.Struct({ type: Schema.Literal('tool'), turnId: Schema.String, name: Schema.String }),
  Schema.Struct({ type: Schema.Literal('trace'), turnId: Schema.String, kind: Schema.Literals(['thinking', 'tool', 'result']), text: Schema.String }),
  Schema.Struct({
    type: Schema.Literal('mcp_call'),
    turnId: Schema.String,
    callId: Schema.String,
    server: Schema.String,
    tool: Schema.String,
    arguments: Schema.Unknown,
  }),
  Schema.Struct({ type: Schema.Literal('window'), turnId: Schema.String, window: AgentWindow }),
  Schema.Struct({ type: Schema.Literal('window_close'), turnId: Schema.String, id: Schema.String }),
  Schema.Struct({ type: Schema.Literal('window_record'), turnId: Schema.String, id: Schema.String, seconds: Schema.Number, path: Schema.String }),
  Schema.Struct({ type: Schema.Literal('windows'), turnId: Schema.String, windows: Schema.Array(AgentWindow) }),
  Schema.Struct({ type: Schema.Literal('done'), turnId: Schema.String, reply: Schema.String, usd: Schema.Number }),
  Schema.Struct({ type: Schema.Literal('failed'), turnId: Schema.String, step: Schema.String, reason: Schema.String }),
]);
export type ServerFrame = typeof ServerFrame.Type;

export const TurnRecord = Schema.Struct({
  turnId: Schema.String,
  startedAt: Schema.Number,
  endedAt: Schema.optional(Schema.Number),
  input: Schema.String,
  status: Schema.Literals(['running', 'done', 'failed', 'cancelled']),
  reply: Schema.optional(Schema.String),
  tools: Schema.Array(Schema.String),
  draws: Schema.Array(DrawShape),
  usd: Schema.Number,
  error: Schema.optional(Schema.Struct({ step: Schema.String, reason: Schema.String })),
});
export type TurnRecord = typeof TurnRecord.Type;

export const ClientFrameJson = Schema.fromJsonString(ClientFrame);
export const ServerFrameJson = Schema.fromJsonString(ServerFrame);
export const TurnRecordsJson = Schema.fromJsonString(Schema.Array(TurnRecord));
