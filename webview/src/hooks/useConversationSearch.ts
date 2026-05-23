/**
 * In-conversation text search hook.
 *
 * Iron Law: this hook is driven by `messagesSignal` (a value that changes
 * whenever the rendered messages change — see ChatScreen integration). It
 * is NOT driven by streaming/lifecycle events, which guarantees identical
 * behavior between live conversations and historical session replay.
 *
 * The match algorithm is intentionally simple:
 *   1. TreeWalker scans every text node inside the messages container,
 *      skipping nodes inside <pre><code> blocks (those are matched at the
 *      block level — see decision in the implementation plan).
 *   2. Plain-text matches are wrapped with <mark class="cc-search-match">.
 *   3. <pre> blocks whose `textContent` contains the query are tagged with
 *      `.cc-search-block-match`. The match index points at the <pre>; the
 *      <mark> at that index is the <pre> itself for navigation.
 *
 * Cleanup unwraps every <mark> and removes every `.cc-search-block-match`
 * class — leaving zero residue, as required by the MVP acceptance list.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ConversationSearchMatch } from '../components/ConversationSearch/types';

export interface UseConversationSearchOptions {
  /** The container we scan + decorate. Usually `.messages-container`. */
  containerRef: React.RefObject<HTMLElement | null>;
  /**
   * Value that changes whenever rendered messages change. Drives re-scan.
   * Typically derived from `mergedMessages.length` + last message stamp.
   */
  messagesSignal: string | number;
  /**
   * Called right before each scan. Returns the number of messages that were
   * just revealed. Used to surface a `Expanded N earlier messages` hint.
   *
   * When the panel is open we want to scan the entire conversation, so
   * collapsed messages must be expanded first.
   */
  ensureRevealed?: () => number;
  /** Optional opt-out for tests. Defaults to 180ms. */
  debounceMs?: number;
  /** Whether to scan + maintain highlights at all. Toggle to enable/disable. */
  enabled: boolean;
}

export interface UseConversationSearchReturn {
  /** Raw user input. */
  query: string;
  /** Setter — caller wires to <input onChange>. */
  setQuery: (next: string) => void;
  /** All matches in document order. */
  matches: ConversationSearchMatch[];
  /** 0-based current match index. -1 when there is no current match. */
  currentIndex: number;
  /** Move to the next match (wraps). No-op when matches is empty. */
  next: () => void;
  /** Move to the previous match (wraps). No-op when matches is empty. */
  previous: () => void;
  /** True while a debounced scan is pending. */
  isSearching: boolean;
  /** Number of messages auto-revealed by the most recent scan (0 if none). */
  expandedCount: number;
  /** Clear query + remove all DOM highlights. */
  clear: () => void;
}

/** CSS class names — kept here so the cleanup logic and CSS match. */
const MARK_CLASS = 'cc-search-match';
const CURRENT_CLASS = 'is-current';
const BLOCK_MATCH_CLASS = 'cc-search-block-match';

/**
 * Treewalker NodeFilter that returns FILTER_REJECT for any text node that
 * lives inside a <pre>, a <style>, a <script>, or an existing <mark> we own.
 * We also reject text inside attribute editors / inputs / textareas.
 */
function buildNodeFilter(): NodeFilter {
  return {
    acceptNode(node: Node): number {
      const text = node.nodeValue;
      if (!text || !text.trim()) return NodeFilter.FILTER_REJECT;
      let parent = node.parentElement;
      while (parent) {
        const tag = parent.tagName;
        if (tag === 'PRE' || tag === 'SCRIPT' || tag === 'STYLE' ||
            tag === 'INPUT' || tag === 'TEXTAREA') {
          return NodeFilter.FILTER_REJECT;
        }
        if (parent.classList.contains(MARK_CLASS)) {
          return NodeFilter.FILTER_REJECT;
        }
        parent = parent.parentElement;
      }
      return NodeFilter.FILTER_ACCEPT;
    },
  };
}

/**
 * Remove every search-related decoration from `container`.
 * Idempotent — safe to call on a non-decorated container.
 *
 * `normalize()` is called once per *unique* parent node at the end,
 * giving O(n) overall instead of O(n²) when there are many marks under
 * the same parent (per code review feedback).
 */
export function clearSearchDecorations(container: HTMLElement | null): void {
  if (!container) return;
  // Unwrap <mark.cc-search-match>
  const marks = container.querySelectorAll(`mark.${MARK_CLASS}`);
  const dirtyParents = new Set<Node>();
  marks.forEach((mark) => {
    const parent = mark.parentNode;
    if (!parent) return;
    while (mark.firstChild) {
      parent.insertBefore(mark.firstChild, mark);
    }
    parent.removeChild(mark);
    dirtyParents.add(parent);
  });
  // Coalesce adjacent text nodes that we just split apart — once per parent.
  dirtyParents.forEach((p) => {
    if (p instanceof Element) p.normalize();
    else (p as Node & { normalize?: () => void }).normalize?.();
  });
  // Strip code-block tags
  const blocks = container.querySelectorAll(`.${BLOCK_MATCH_CLASS}`);
  blocks.forEach((el) => el.classList.remove(BLOCK_MATCH_CLASS, CURRENT_CLASS));
}

interface MatchOccurrence {
  textNode: Text;
  start: number;
  end: number;
}

/**
 * Build a list of (textNode, start, end) occurrences for `query` inside
 * `container`. Case-insensitive. Skips empty queries.
 *
 * Exported for testing.
 */
export function collectTextMatches(
  container: HTMLElement,
  query: string,
): MatchOccurrence[] {
  if (!query) return [];
  const lowerQuery = query.toLowerCase();
  const walker = container.ownerDocument.createTreeWalker(
    container,
    NodeFilter.SHOW_TEXT,
    buildNodeFilter(),
  );
  const occurrences: MatchOccurrence[] = [];
  let node = walker.nextNode();
  while (node) {
    const text = node.nodeValue ?? '';
    const lower = text.toLowerCase();
    let from = 0;
    while (from <= lower.length - lowerQuery.length) {
      const found = lower.indexOf(lowerQuery, from);
      if (found === -1) break;
      occurrences.push({
        textNode: node as Text,
        start: found,
        end: found + query.length,
      });
      from = found + query.length;
    }
    node = walker.nextNode();
  }
  return occurrences;
}

/**
 * Wrap each occurrence with `<mark class="cc-search-match">`.
 * Returns the list of mark elements in document order.
 *
 * Important: we process occurrences belonging to the same text node from
 * right to left, so earlier ranges are not invalidated by `splitText`.
 */
function wrapOccurrences(
  occurrences: MatchOccurrence[],
  doc: Document,
): HTMLElement[] {
  // Group by text node
  const byNode = new Map<Text, MatchOccurrence[]>();
  for (const occ of occurrences) {
    const list = byNode.get(occ.textNode);
    if (list) list.push(occ);
    else byNode.set(occ.textNode, [occ]);
  }

  // We build the result in original (left-to-right) order by recording
  // mark elements as we create them — but the actual DOM mutations need
  // to happen right-to-left within each node.
  const marks: HTMLElement[] = [];
  const marksByOccurrence = new Map<MatchOccurrence, HTMLElement>();

  byNode.forEach((occs) => {
    // Sort right-to-left so splitting later ranges first preserves earlier
    // ranges. occs share the same source node.
    const sorted = [...occs].sort((a, b) => b.start - a.start);
    sorted.forEach((occ) => {
      // After previous right-side splits, occ.textNode is still the LEFT
      // remnant for this occurrence's range, so splitText(start) works.
      const afterStart = occ.textNode.splitText(occ.start);
      // afterStart now starts at the match; split again at length.
      afterStart.splitText(occ.end - occ.start);
      const mark = doc.createElement('mark');
      mark.className = MARK_CLASS;
      mark.textContent = afterStart.nodeValue ?? '';
      afterStart.parentNode?.replaceChild(mark, afterStart);
      marksByOccurrence.set(occ, mark);
    });
  });

  // Now produce left-to-right list using the original `occurrences` order.
  for (const occ of occurrences) {
    const m = marksByOccurrence.get(occ);
    if (m) marks.push(m);
  }
  return marks;
}

/**
 * Tag every `<pre>` block whose `textContent` contains the query.
 * Returns the list of <pre> elements that got the tag.
 */
function tagCodeBlocks(container: HTMLElement, query: string): HTMLElement[] {
  if (!query) return [];
  const lowerQuery = query.toLowerCase();
  const result: HTMLElement[] = [];
  const pres = container.querySelectorAll('pre');
  pres.forEach((pre) => {
    const text = (pre.textContent ?? '').toLowerCase();
    if (text.includes(lowerQuery)) {
      pre.classList.add(BLOCK_MATCH_CLASS);
      result.push(pre as HTMLElement);
    }
  });
  return result;
}

export function useConversationSearch(
  options: UseConversationSearchOptions,
): UseConversationSearchReturn {
  const { containerRef, messagesSignal, ensureRevealed, debounceMs = 180, enabled } = options;
  const [query, setQuery] = useState<string>('');
  const [matches, setMatches] = useState<ConversationSearchMatch[]>([]);
  const [currentIndex, setCurrentIndex] = useState<number>(-1);
  const [isSearching, setIsSearching] = useState<boolean>(false);
  const [expandedCount, setExpandedCount] = useState<number>(0);
  const debounceRef = useRef<number | null>(null);
  const lastQueryRef = useRef<string>('');

  /** Actually scan the DOM. */
  const performScan = useCallback((rawQuery: string): void => {
    const container = containerRef.current;
    if (!container) {
      setMatches([]);
      setCurrentIndex(-1);
      return;
    }
    clearSearchDecorations(container);
    const trimmed = rawQuery.trim();
    if (!trimmed) {
      setMatches([]);
      setCurrentIndex(-1);
      return;
    }
    const doc = container.ownerDocument;
    const occurrences = collectTextMatches(container, trimmed);
    const wrapped = wrapOccurrences(occurrences, doc);
    const blocks = tagCodeBlocks(container, trimmed);

    // Merge: we want matches in document order. Each wrapped <mark> + each
    // <pre> block is one match. To sort, use compareDocumentPosition.
    const all: ConversationSearchMatch[] = [];
    wrapped.forEach((mark, i) => {
      all.push({
        id: `m-${i}-${mark.textContent ?? ''}`,
        markElement: mark,
        blockElement: null,
      });
    });
    blocks.forEach((pre, i) => {
      all.push({
        id: `b-${i}`,
        markElement: null,
        blockElement: pre,
      });
    });
    all.sort((a, b) => {
      const aNode = a.markElement ?? a.blockElement;
      const bNode = b.markElement ?? b.blockElement;
      if (!aNode || !bNode) return 0;
      // Bit 4 = follows; bit 2 = precedes
      const pos = aNode.compareDocumentPosition(bNode);
      if (pos & Node.DOCUMENT_POSITION_FOLLOWING) return -1;
      if (pos & Node.DOCUMENT_POSITION_PRECEDING) return 1;
      return 0;
    });

    setMatches(all);
    setCurrentIndex(all.length > 0 ? 0 : -1);
  }, [containerRef]);

  /** Debounced re-scan whenever query / signal / enabled changes. */
  useEffect(() => {
    if (!enabled) {
      clearSearchDecorations(containerRef.current);
      setMatches([]);
      setCurrentIndex(-1);
      setIsSearching(false);
      return;
    }
    if (debounceRef.current !== null) {
      window.clearTimeout(debounceRef.current);
    }
    // Reveal collapsed messages before scanning so the scan sees the whole
    // conversation. This is the critical line that makes search useful in
    // long sessions — per the agreed design.
    if (ensureRevealed && lastQueryRef.current !== query) {
      const revealed = ensureRevealed();
      setExpandedCount(revealed);
    }
    lastQueryRef.current = query;
    setIsSearching(true);
    debounceRef.current = window.setTimeout(() => {
      debounceRef.current = null;
      performScan(query);
      setIsSearching(false);
    }, debounceMs);
    return () => {
      if (debounceRef.current !== null) {
        window.clearTimeout(debounceRef.current);
        debounceRef.current = null;
      }
    };
  }, [query, messagesSignal, enabled, ensureRevealed, debounceMs, performScan, containerRef]);

  /** Sync `.is-current` class with currentIndex. */
  useEffect(() => {
    if (!enabled) return;
    const target = matches[currentIndex];
    matches.forEach((m, i) => {
      if (m.markElement) m.markElement.classList.toggle(CURRENT_CLASS, i === currentIndex);
      if (m.blockElement) m.blockElement.classList.toggle(CURRENT_CLASS, i === currentIndex);
    });
    if (!target) return;
    const el = target.markElement ?? target.blockElement;
    if (!el) return;
    try {
      el.scrollIntoView({ block: 'center', behavior: 'smooth' });
    } catch {
      // jsdom may not implement scrollIntoView
    }
  }, [currentIndex, matches, enabled]);

  /** Cleanup on unmount or when disabled. */
  useEffect(() => {
    return () => {
      clearSearchDecorations(containerRef.current);
    };
  }, [containerRef]);

  const next = useCallback(() => {
    setCurrentIndex((i) => {
      if (matches.length === 0) return -1;
      return (i + 1) % matches.length;
    });
  }, [matches.length]);

  const previous = useCallback(() => {
    setCurrentIndex((i) => {
      if (matches.length === 0) return -1;
      return (i - 1 + matches.length) % matches.length;
    });
  }, [matches.length]);

  const clear = useCallback(() => {
    setQuery('');
    setMatches([]);
    setCurrentIndex(-1);
    setExpandedCount(0);
    clearSearchDecorations(containerRef.current);
  }, [containerRef]);

  return useMemo(
    () => ({ query, setQuery, matches, currentIndex, next, previous, isSearching, expandedCount, clear }),
    [query, matches, currentIndex, next, previous, isSearching, expandedCount, clear],
  );
}
