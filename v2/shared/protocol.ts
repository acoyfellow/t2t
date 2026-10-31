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

export const TurnRequest = Schema.Struct({
  type: Schema.Literal('turn'),
  turnId: Schema.String,
  text: Schema.String,
  screen: Schema.optional(Schema.Struct({ width: Schema.Number, height: Schema.Number })),
});
export type TurnRequest = typeof TurnRequest.Type;

export const ClientFrame = Schema.Union([TurnRequest, Schema.Struct({ type: Schema.Literal('cancel'), turnId: Schema.String })]);
export type ClientFrame = typeof ClientFrame.Type;

export const ServerFrame = Schema.Union([
  Schema.Struct({ type: Schema.Literal('text'), turnId: Schema.String, text: Schema.String }),
  Schema.Struct({ type: Schema.Literal('draw'), turnId: Schema.String, shape: DrawShape }),
  Schema.Struct({ type: Schema.Literal('clear'), turnId: Schema.String }),
  Schema.Struct({ type: Schema.Literal('tool'), turnId: Schema.String, name: Schema.String }),
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
