/**
 * ConversationSearch — floating in-page search panel for the chat view.
 *
 * Behavior contract (see project rule "codex-history-replay-pitfalls.md"
 * Iron Law 1: search must work the same in live and replay modes; this is
 * achieved by driving the search via `messagesSignal` instead of stream
 * lifecycle events).
 */
import { memo, useCallback, useEffect, useMemo, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useConversationSearch } from '../../hooks/useConversationSearch';
import type { MessageListRevealHandle } from './types';

export interface ConversationSearchProps {
  /** True when the panel is visible. Controlled by the parent (UIState). */
  open: boolean;
  /** Called when the user closes the panel (Esc / × button / view change). */
  onClose: () => void;
  /** The DOM container we search inside (the messages list scroll area). */
  containerRef: React.RefObject<HTMLElement | null>;
  /**
   * Signal that changes whenever the rendered messages change. Used to
   * trigger a re-scan after streaming appends, after history loads, after
   * collapse is expanded, etc.
   */
  messagesSignal: string | number;
  /** Imperative handle for revealing collapsed earlier messages. */
  messageListRef?: React.RefObject<MessageListRevealHandle | null>;
  /** Optional ref to scroll-behavior's auto-scroll flag for cooperation. */
  isAutoScrollingRef?: React.MutableRefObject<boolean>;
}

export const ConversationSearch = memo(function ConversationSearch({
  open,
  onClose,
  containerRef,
  messagesSignal,
  messageListRef,
  isAutoScrollingRef,
}: ConversationSearchProps) {
  const { t } = useTranslation();
  const inputRef = useRef<HTMLInputElement | null>(null);

  /** Force-reveal collapsed earlier messages so we can search the whole thread. */
  const ensureRevealed = useCallback((): number => {
    const handle = messageListRef?.current;
    if (!handle) return 0;
    return handle.revealAll();
  }, [messageListRef]);

  const {
    query, setQuery,
    matches, currentIndex,
    next, previous,
    isSearching, expandedCount,
    clear,
  } = useConversationSearch({
    containerRef,
    messagesSignal,
    ensureRevealed,
    enabled: open,
  });

  // Auto-focus when the panel opens.
  useEffect(() => {
    if (!open) return;
    // Use rAF so it focuses after layout — needed when the panel just mounted.
    const id = requestAnimationFrame(() => inputRef.current?.focus());
    return () => cancelAnimationFrame(id);
  }, [open]);

  // Reveal collapsed earlier messages on panel open, so the user sees the
  // full scope they are about to search BEFORE typing.
  // Per code review: doing this here (instead of waiting for the first
  // keystroke) avoids the "I opened search but my old messages are still
  // collapsed" confusion.
  useEffect(() => {
    if (!open) return;
    messageListRef?.current?.revealAll();
  }, [open, messageListRef]);

  // Mark autoscroll while we are navigating, to avoid scroll-behavior
  // pausing auto-follow due to our scrollIntoView calls. The flag is
  // self-cleared by useScrollBehavior after one rAF.
  useEffect(() => {
    if (!open || currentIndex < 0) return;
    if (isAutoScrollingRef) isAutoScrollingRef.current = true;
  }, [currentIndex, open, isAutoScrollingRef]);

  const handleClose = useCallback(() => {
    clear();
    onClose();
  }, [clear, onClose]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.nativeEvent.isComposing) return;
    if (e.key === 'Enter') {
      e.preventDefault();
      e.stopPropagation();
      if (e.shiftKey) previous();
      else next();
      return;
    }
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      handleClose();
      return;
    }
    if (e.key === 'F3') {
      e.preventDefault();
      if (e.shiftKey) previous();
      else next();
      return;
    }
  }, [next, previous, handleClose]);

  const counterText = useMemo(() => {
    if (!query.trim()) return '';
    if (isSearching) return t('chat.search.searching', { defaultValue: 'Searching…' });
    if (matches.length === 0) return t('chat.search.noResults', { defaultValue: 'No results' });
    return t('chat.search.counter', {
      defaultValue: '{{current}}/{{total}}',
      current: currentIndex + 1,
      total: matches.length,
    });
  }, [query, isSearching, matches.length, currentIndex, t]);

  if (!open) return null;

  const hasResults = matches.length > 0;
  const noResults = query.trim().length > 0 && !isSearching && matches.length === 0;

  return (
    <div
      className="cc-search-panel"
      role="search"
      aria-label={t('chat.search.ariaLabel', { defaultValue: 'Search in conversation' })}
      onMouseDown={(e) => {
        // Prevent clicks inside the panel from blurring the input
        if (e.target !== inputRef.current) e.preventDefault();
      }}
    >
      <span className="cc-search-icon codicon codicon-search" aria-hidden="true" />
      <input
        ref={inputRef}
        type="text"
        className={`cc-search-input${noResults ? ' is-no-results' : ''}`}
        placeholder={t('chat.search.placeholder', { defaultValue: 'Search in conversation…' })}
        aria-label={t('chat.search.ariaLabel', { defaultValue: 'Search in conversation' })}
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        onKeyDown={handleKeyDown}
        spellCheck={false}
        autoComplete="off"
      />
      <span className="cc-search-counter" aria-live="polite">
        {counterText}
      </span>
      <button
        type="button"
        className="cc-search-btn"
        onClick={previous}
        disabled={!hasResults}
        title={t('chat.search.previous', { defaultValue: 'Previous match (Shift+Enter)' })}
        aria-label={t('chat.search.previous', { defaultValue: 'Previous match' })}
      >
        <span className="codicon codicon-arrow-up" />
      </button>
      <button
        type="button"
        className="cc-search-btn"
        onClick={next}
        disabled={!hasResults}
        title={t('chat.search.next', { defaultValue: 'Next match (Enter)' })}
        aria-label={t('chat.search.next', { defaultValue: 'Next match' })}
      >
        <span className="codicon codicon-arrow-down" />
      </button>
      <button
        type="button"
        className="cc-search-btn"
        onClick={handleClose}
        title={t('chat.search.close', { defaultValue: 'Close (Esc)' })}
        aria-label={t('chat.search.close', { defaultValue: 'Close' })}
      >
        <span className="codicon codicon-close" />
      </button>
      {expandedCount > 0 && (
        <div className="cc-search-hint" role="status">
          {t('chat.search.expandedHint', {
            defaultValue: 'Expanded {{count}} earlier messages',
            count: expandedCount,
          })}
        </div>
      )}
    </div>
  );
});
