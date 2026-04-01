import { renderHook } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { useMessageProcessing } from './useMessageProcessing.js';
import type { ClaudeMessage } from '../types/index.js';

const t = ((key: string) => key) as any;

const makeMessage = (
  type: ClaudeMessage['type'],
  content: string,
  extra?: Partial<ClaudeMessage>,
): ClaudeMessage => ({
  type,
  content,
  timestamp: new Date().toISOString(),
  ...extra,
});

describe('useMessageProcessing', () => {
  it('keeps assistant turns separate when a hidden message sits between them', () => {
    const messages: ClaudeMessage[] = [
      makeMessage('assistant', 'First assistant reply', {
        __turnId: 1,
        raw: { content: [{ type: 'text', text: 'First assistant reply' }] } as any,
        timestamp: '2026-04-01T10:00:00.000Z',
      }),
      makeMessage('user', '', {
        raw: '<command-name>/aimax:auto</command-name>\n<command-args>follow up</command-args>' as any,
        timestamp: '2026-04-01T10:00:01.000Z',
      }),
      makeMessage('assistant', 'Second assistant reply', {
        __turnId: 2,
        raw: { content: [{ type: 'text', text: 'Second assistant reply' }] } as any,
        timestamp: '2026-04-01T10:00:02.000Z',
      }),
    ];

    const { result } = renderHook(() =>
      useMessageProcessing({
        messages,
        currentSessionId: 'session-1',
        t,
      }),
    );

    expect(result.current.mergedMessages).toHaveLength(2);
    expect(result.current.mergedMessages.map((message) => message.content)).toEqual([
      'First assistant reply',
      'Second assistant reply',
    ]);
    expect(result.current.mergedMessages.map((message) => message.__turnId)).toEqual([1, 2]);
  });
});
