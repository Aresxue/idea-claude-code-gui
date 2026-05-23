/**
 * Tests for the ConversationSearch panel UI.
 */
import { act, fireEvent, render, screen } from '@testing-library/react';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ConversationSearch } from './index';
import type { MessageListRevealHandle } from './types';

// Stub i18next so `t(key, { defaultValue })` returns the default text.
vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (_key: string, options?: { defaultValue?: string; current?: number; total?: number; count?: number }) => {
      if (!options) return _key;
      if (options.defaultValue?.includes('{{current}}') && typeof options.current === 'number') {
        return `${options.current}/${options.total}`;
      }
      if (options.defaultValue?.includes('{{count}}') && typeof options.count === 'number') {
        return options.defaultValue.replace('{{count}}', String(options.count));
      }
      return options.defaultValue ?? _key;
    },
  }),
}));

function setupContainer(html: string): React.RefObject<HTMLDivElement> {
  const container = document.createElement('div');
  container.innerHTML = html;
  document.body.appendChild(container);
  return { current: container } as React.RefObject<HTMLDivElement>;
}

beforeEach(() => {
  document.body.innerHTML = '';
  vi.useFakeTimers();
});

describe('ConversationSearch', () => {
  it('does not render when open=false', () => {
    const ref = setupContainer('<p>hi</p>');
    render(
      <ConversationSearch
        open={false}
        onClose={() => {}}
        containerRef={ref}
        messagesSignal="1"
      />,
    );
    expect(screen.queryByRole('search')).toBeNull();
  });

  it('renders input + buttons when open', () => {
    const ref = setupContainer('<p>hi</p>');
    render(
      <ConversationSearch
        open
        onClose={() => {}}
        containerRef={ref}
        messagesSignal="1"
      />,
    );
    expect(screen.getByRole('search')).toBeTruthy();
    expect(screen.getByPlaceholderText(/Search in conversation/i)).toBeTruthy();
  });

  it('Esc key closes the panel', () => {
    const ref = setupContainer('<p>hello world</p>');
    const onClose = vi.fn();
    render(
      <ConversationSearch
        open
        onClose={onClose}
        containerRef={ref}
        messagesSignal="1"
      />,
    );
    const input = screen.getByPlaceholderText(/Search in conversation/i);
    fireEvent.keyDown(input, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('Enter navigates to next match', () => {
    const ref = setupContainer(
      '<p>foo bar foo</p><p>another foo</p>',
    );
    render(
      <ConversationSearch
        open
        onClose={() => {}}
        containerRef={ref}
        messagesSignal="1"
      />,
    );
    const input = screen.getByPlaceholderText(/Search/i);
    fireEvent.change(input, { target: { value: 'foo' } });
    // Wait for debounce (default 180ms)
    act(() => { vi.advanceTimersByTime(250); });
    // counter should appear with 3 matches
    expect(screen.getByText(/^1\/3$/)).toBeTruthy();
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(screen.getByText(/^2\/3$/)).toBeTruthy();
    fireEvent.keyDown(input, { key: 'Enter' });
    fireEvent.keyDown(input, { key: 'Enter' });
    // Should wrap to 1
    expect(screen.getByText(/^1\/3$/)).toBeTruthy();
  });

  it('Shift+Enter goes to previous', () => {
    const ref = setupContainer('<p>x y x y</p>');
    render(
      <ConversationSearch
        open
        onClose={() => {}}
        containerRef={ref}
        messagesSignal="1"
      />,
    );
    const input = screen.getByPlaceholderText(/Search/i);
    fireEvent.change(input, { target: { value: 'x' } });
    act(() => { vi.advanceTimersByTime(250); });
    expect(screen.getByText(/^1\/2$/)).toBeTruthy();
    fireEvent.keyDown(input, { key: 'Enter', shiftKey: true });
    // Wraps to the last match
    expect(screen.getByText(/^2\/2$/)).toBeTruthy();
  });

  it('invokes revealAll on the MessageList ref when query begins', () => {
    const ref = setupContainer('<p>hello</p>');
    const reveal: MessageListRevealHandle = { revealAll: vi.fn(() => 5) };
    const messageListRef = { current: reveal } as React.RefObject<MessageListRevealHandle>;
    render(
      <ConversationSearch
        open
        onClose={() => {}}
        containerRef={ref}
        messagesSignal="1"
        messageListRef={messageListRef}
      />,
    );
    const input = screen.getByPlaceholderText(/Search/i);
    fireEvent.change(input, { target: { value: 'h' } });
    act(() => { vi.advanceTimersByTime(250); });
    expect(reveal.revealAll).toHaveBeenCalled();
  });

  it('shows "No results" message when query has no matches', () => {
    const ref = setupContainer('<p>hello world</p>');
    render(
      <ConversationSearch
        open
        onClose={() => {}}
        containerRef={ref}
        messagesSignal="1"
      />,
    );
    const input = screen.getByPlaceholderText(/Search/i);
    fireEvent.change(input, { target: { value: 'absent' } });
    act(() => { vi.advanceTimersByTime(250); });
    expect(screen.getByText('No results')).toBeTruthy();
  });
});
