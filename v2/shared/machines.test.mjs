import { test } from 'node:test';
import assert from 'node:assert/strict';
import { machines, overlayMachine, mcpMachine, gatewayMachine, holdMachine, turnMachine, jobMachine, indicatorMachine, panelMachine, statsMachine } from './fsm.mjs';

const cases = [
  [overlayMachine, 'idle', 'HOLD', 'listening'],
  [overlayMachine, 'listening', 'RELEASE_AGENT', 'thinking'],
  [overlayMachine, 'listening', 'RELEASE_DICTATE', 'idle'],
  [overlayMachine, 'thinking', 'TEXT', 'speaking'],
  [overlayMachine, 'thinking', 'TIMEOUT', 'idle'],
  [overlayMachine, 'speaking', 'DONE', 'idle'],
  [overlayMachine, 'idle', 'TEXT', null],
  [overlayMachine, 'idle', 'DONE', null],
  [mcpMachine, 'idle', 'CONNECT', 'connecting'],
  [mcpMachine, 'connecting', 'CONNECTED', 'connected'],
  [mcpMachine, 'connecting', 'NEED_LOGIN', 'login-needed'],
  [mcpMachine, 'connected', 'REFRESH', 'connecting'],
  [mcpMachine, 'login-needed', 'SIGNIN', 'connecting'],
  [mcpMachine, 'disconnected', 'CONNECT', 'connecting'],
  [mcpMachine, 'connected', 'SIGNIN', null],
  [gatewayMachine, 'unknown', 'REFRESH', 'refreshing'],
  [gatewayMachine, 'refreshing', 'OK', 'ok'],
  [gatewayMachine, 'refreshing', 'NEED_LOGIN', 'login-needed'],
  [gatewayMachine, 'ok', 'REFRESH', 'refreshing'],
  [gatewayMachine, 'ok', 'OK', null],
  [holdMachine, 'none', 'START_AGENT', 'agent'],
  [holdMachine, 'agent', 'STOP', 'none'],
  [holdMachine, 'dictate', 'START_AGENT', 'agent'],
  [holdMachine, 'none', 'STOP', null],
  [turnMachine, 'running', 'DONE', 'done'],
  [turnMachine, 'running', 'CANCEL', 'cancelled'],
  [turnMachine, 'done', 'DONE', null],
  [jobMachine, 'idle', 'START', 'running'],
  [jobMachine, 'running', 'LOST', 'abandoned'],
  [jobMachine, 'abandoned', 'START', 'running'],
  [indicatorMachine, 'hidden', 'SHOW', 'active'],
  [indicatorMachine, 'active', 'HIDE', 'hidden'],
  [panelMachine, 'loading', 'LOADED', 'ready'],
  [panelMachine, 'loading', 'FAILED', 'error'],
  [panelMachine, 'error', 'RETRY', 'loading'],
  [statsMachine, 'not-imported', 'IMPORT', 'imported'],
  [statsMachine, 'imported', 'IMPORT', 'imported'],
];

for (const [machine, state, event, expected] of cases) {
  test(`${machine.name ?? 'machine'} ${state} + ${event} = ${expected}`, () => {
    assert.equal(machine.send(state, event), expected);
    assert.equal(machine.can(state, event), expected !== null);
  });
}

test('every machine has an initial state in its table', () => {
  for (const machine of Object.values(machines)) assert.ok(machine.transitions[machine.initial], machine.initial);
});

test('wire strings unchanged', () => {
  assert.deepEqual(Object.keys(overlayMachine.transitions).sort(), ['idle', 'listening', 'speaking', 'thinking']);
  assert.deepEqual(Object.keys(mcpMachine.transitions).sort(), ['connected', 'connecting', 'disconnected', 'error', 'idle', 'login-needed']);
  assert.deepEqual(Object.keys(gatewayMachine.transitions).sort(), ['login-needed', 'ok', 'push-failed', 'refreshing', 'unknown']);
});
