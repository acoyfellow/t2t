export type TurnState = 'running' | 'done' | 'failed' | 'cancelled';
export const turnNext = (state: string, event: string): TurnState | null => {
  if (state !== 'running') return null;
  return ({ DONE: 'done', FAILED: 'failed', CANCEL: 'cancelled' } as Record<string, TurnState>)[event] ?? null;
};
