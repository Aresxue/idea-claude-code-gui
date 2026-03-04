/**
 * Settings-based Permission Checker.
 * Reads permissions.allow / permissions.deny from ~/.claude/settings.json
 * and project-level .claude/settings.json, then matches tool invocations
 * against those rules.
 *
 * Cache strategy: pure mtime-driven (no TTL). Each call checks file mtime
 * via statSync (~0.01ms inode metadata read). Only re-reads file content
 * when mtime changes.
 */

import { readFileSync, existsSync, statSync } from 'fs';
import { join, resolve, isAbsolute } from 'path';
import { getRealHomeDir, getClaudeDir } from './path-utils.js';

// ========== Debug logging ==========
function debugLog(tag, message, data = null) {
  const timestamp = new Date().toISOString();
  const dataStr = data ? ` | Data: ${JSON.stringify(data)}` : '';
  console.log(`[${timestamp}][PERM_DEBUG][${tag}] ${message}${dataStr}`);
}

// ========== Project root ==========
function getProjectRoot() {
  return process.env.IDEA_PROJECT_PATH || process.env.PROJECT_PATH || null;
}

// ========== Mtime-driven cache ==========

// Cache structure: { rules: { allow: ParsedRule[], deny: ParsedRule[] }, fileMtime: number }
let globalSettingsCache = null;
let projectSettingsCache = null;

function getFileMtime(filePath) {
  try {
    return statSync(filePath).mtimeMs;
  } catch {
    return 0;
  }
}

function loadPermissionRules(settingsPath) {
  try {
    if (false === existsSync(settingsPath)) {
      return { allow: [], deny: [] };
    }
    const content = readFileSync(settingsPath, 'utf8');
    const settings = JSON.parse(content);
    const permissions = settings?.permissions;
    if (null == permissions) {
      return { allow: [], deny: [] };
    }
    const allowRuleList = (permissions.allow || []).map(parseRule).filter(Boolean);
    const denyRuleList = (permissions.deny || []).map(parseRule).filter(Boolean);
    return { allow: allowRuleList, deny: denyRuleList };
  } catch (error) {
    debugLog('SETTINGS_PERM', `load permission rules fail: ${error.message}`);
    return { allow: [], deny: [] };
  }
}

function getGlobalRules() {
  const settingsPath = join(getClaudeDir(), 'settings.json');
  const currentMtime = getFileMtime(settingsPath);
  if (null != globalSettingsCache && globalSettingsCache.fileMtime === currentMtime) {
    return globalSettingsCache.rules;
  }
  const rules = loadPermissionRules(settingsPath);
  globalSettingsCache = { rules, fileMtime: currentMtime };
  debugLog('SETTINGS_PERM', `global rules reloaded`, { allowCount: rules.allow.length, denyCount: rules.deny.length });
  return rules;
}

function getProjectRules() {
  const projectRoot = getProjectRoot();
  if (null == projectRoot) {
    return { allow: [], deny: [] };
  }
  const settingsPath = join(projectRoot, '.claude', 'settings.json');
  const currentMtime = getFileMtime(settingsPath);
  if (null != projectSettingsCache
    && projectSettingsCache.projectRoot === projectRoot
    && projectSettingsCache.fileMtime === currentMtime) {
    return projectSettingsCache.rules;
  }
  const rules = loadPermissionRules(settingsPath);
  projectSettingsCache = { rules, fileMtime: currentMtime, projectRoot };
  debugLog('SETTINGS_PERM', `project rules reloaded`, { projectRoot, allowCount: rules.allow.length, denyCount: rules.deny.length });
  return rules;
}

// ========== Rule parsing ==========

/**
 * Parse a permission rule string into a structured object.
 *
 * Supported formats:
 *   With pattern:    "ToolName(pattern)"
 *   Without pattern: "ToolName" or "mcp__serverName__toolName"
 *
 * Bash with colon:    "Bash(ls:./**)"   → { toolName, commandPrefix, argPattern }
 * Bash without colon: "Bash(git status*)" → { toolName, pattern }
 * File tools:         "Read(./**)"      → { toolName, pattern }
 * WebFetch:           "WebFetch(domain:github.com)" → { toolName, qualifier, qualifierValue }
 * Tool-name-only:     "TodoWrite"       → { toolName, pattern: null, toolNameOnly: true }
 * MCP:                "mcp__server__tool" → { toolName, pattern: null, toolNameOnly: true }
 */
function parseRule(ruleStr) {
  if (null == ruleStr || 'string' !== typeof ruleStr) {
    return null;
  }
  const trimmed = ruleStr.trim();

  // try ToolName(pattern) format first
  const match = trimmed.match(/^(\w+)\((.+)\)$/);
  if (null != match) {
    const toolName = match[1];
    const innerPattern = match[2];

    if ('Bash' === toolName) {
      const colonIndex = innerPattern.indexOf(':');
      if (colonIndex > 0) {
        const commandPrefix = innerPattern.substring(0, colonIndex);
        const argPattern = innerPattern.substring(colonIndex + 1);
        return { toolName, pattern: innerPattern, commandPrefix, argPattern, raw: trimmed };
      }
      return { toolName, pattern: innerPattern, commandPrefix: null, argPattern: null, raw: trimmed };
    }

    if ('WebFetch' === toolName) {
      const colonIndex = innerPattern.indexOf(':');
      if (colonIndex > 0) {
        const qualifier = innerPattern.substring(0, colonIndex);
        const qualifierValue = innerPattern.substring(colonIndex + 1);
        return { toolName, pattern: innerPattern, qualifier, qualifierValue, raw: trimmed };
      }
    }

    return { toolName, pattern: innerPattern, raw: trimmed };
  }

  // tool-name-only format: "TodoWrite", "mcp__serverName__toolName", "mcp__server__*", etc.
  // word chars + wildcards (* ?)
  if (/^[\w*?]+$/.test(trimmed)) {
    return { toolName: trimmed, pattern: null, toolNameOnly: true, raw: trimmed };
  }

  return null;
}

// ========== Glob matching ==========

/**
 * Simple glob matcher supporting * and ** patterns.
 *
 * @param {string} pattern - the glob pattern
 * @param {string} text - the text to match against
 * @param {boolean} commandMode - if true, * matches any char including space;
 *                                 if false (path mode), * matches any char except /
 */
function globMatch(pattern, text, commandMode = false) {
  const normalizedPattern = pattern.replace(/\\/g, '/');
  const normalizedText = text.replace(/\\/g, '/');

  let regexStr = '^';
  let i = 0;
  while (i < normalizedPattern.length) {
    const char = normalizedPattern[i];

    if ('*' === char) {
      if (i + 1 < normalizedPattern.length && '*' === normalizedPattern[i + 1]) {
        // ** matches everything including /
        regexStr += '.*';
        i += 2;
        // skip trailing / after **
        if (i < normalizedPattern.length && '/' === normalizedPattern[i]) {
          regexStr += '(?:/)?';
          i++;
        }
        continue;
      }
      // single *
      regexStr += commandMode ? '.*' : '[^/]*';
      i++;
      continue;
    }

    if ('?' === char) {
      regexStr += '[^/]';
      i++;
      continue;
    }

    // escape regex special characters
    if ('.+^${}()|[]\\'.includes(char)) {
      regexStr += '\\' + char;
    } else {
      regexStr += char;
    }
    i++;
  }
  regexStr += '$';

  try {
    return new RegExp(regexStr).test(normalizedText);
  } catch {
    return false;
  }
}

// ========== Path expansion ==========

/**
 * Expand relative path patterns:
 * ./** → {projectRoot}/**
 * ~/path → {homeDir}/path
 * /absolute → unchanged
 */
function expandPathPattern(pattern) {
  if (pattern.startsWith('./') || '.' === pattern) {
    const projectRoot = getProjectRoot();
    if (null == projectRoot) {
      return pattern;
    }
    return join(projectRoot, pattern.substring(2)).replace(/\\/g, '/');
  }
  if (pattern.startsWith('~/') || '~' === pattern) {
    const home = getRealHomeDir();
    return join(home, pattern.substring(2)).replace(/\\/g, '/');
  }
  return pattern;
}

// ========== Tool input extraction ==========

function extractToolInput(toolName, input) {
  if (null == input) {
    return {};
  }

  if ('Bash' === toolName) {
    return { command: input.command || '' };
  }

  // NotebookRead / NotebookEdit use notebook_path
  if ('NotebookRead' === toolName || 'NotebookEdit' === toolName) {
    if (input.notebook_path) {
      return { filePath: input.notebook_path };
    }
  }

  // file-based tools (Read, Write, Edit, Glob, Grep, etc.)
  if (input.file_path) {
    return { filePath: input.file_path };
  }
  if (input.path) {
    return { filePath: input.path };
  }
  if (input.pattern) {
    return { filePath: input.pattern };
  }

  return {};
}

// ========== Rule matching ==========

function matchBashWithPrefix(command, rule) {
  const trimmedCmd = command.trim();
  const spaceIndex = trimmedCmd.indexOf(' ');

  let actualCmd;
  let actualArgs;
  if (spaceIndex < 0) {
    actualCmd = trimmedCmd;
    actualArgs = '';
  } else {
    actualCmd = trimmedCmd.substring(0, spaceIndex);
    actualArgs = trimmedCmd.substring(spaceIndex + 1).trim();
  }

  // command prefix must match exactly
  if (actualCmd !== rule.commandPrefix) {
    return false;
  }

  // wildcard argPattern: match anything
  if ('*' === rule.argPattern) {
    return true;
  }

  const expandedArgPattern = expandPathPattern(rule.argPattern);

  // try matching entire args string first
  if (globMatch(expandedArgPattern, actualArgs, true)) {
    return true;
  }

  // try each individual token (handles flags like -la being mixed in)
  const tokenList = actualArgs.split(/\s+/).filter(t => t.length > 0);
  for (const token of tokenList) {
    // skip flag-like tokens
    if (token.startsWith('-')) {
      continue;
    }

    let resolvedToken = token;
    if (false === isAbsolute(token) && false === token.startsWith('~')) {
      const cwd = getProjectRoot() || process.cwd();
      resolvedToken = resolve(cwd, token).replace(/\\/g, '/');
    } else if (token.startsWith('~/')) {
      resolvedToken = join(getRealHomeDir(), token.substring(2)).replace(/\\/g, '/');
    }

    if (globMatch(expandedArgPattern, resolvedToken)) {
      return true;
    }
  }

  // no args and pattern is permissive
  if ('' === actualArgs) {
    return globMatch(expandedArgPattern, '');
  }

  return false;
}

function matchRule(rule, toolName, input) {
  // tool-name-only rules: match by tool name (exact or glob for MCP patterns)
  if (true === rule.toolNameOnly) {
    // exact match
    if (rule.toolName === toolName) {
      return true;
    }
    // glob match for MCP-style names (e.g., rule "mcp__server__*" matches "mcp__server__listTools")
    if (rule.toolName.includes('*') || rule.toolName.includes('?')) {
      return globMatch(rule.toolName, toolName, true);
    }
    return false;
  }

  if (rule.toolName !== toolName) {
    return false;
  }

  const extracted = extractToolInput(toolName, input);

  if ('Bash' === toolName) {
    const command = extracted.command;
    if (null == command || '' === command) {
      return false;
    }

    if (null != rule.commandPrefix) {
      return matchBashWithPrefix(command, rule);
    }

    // no commandPrefix: glob-match the entire command in command mode
    return globMatch(rule.pattern, command.trim(), true);
  }

  if ('WebFetch' === toolName && 'domain' === rule.qualifier) {
    const url = input?.url || '';
    try {
      const parsedUrl = new URL(url);
      return globMatch(rule.qualifierValue, parsedUrl.hostname);
    } catch {
      return false;
    }
  }

  // file-based tools
  const filePath = extracted.filePath;
  if (null == filePath) {
    return false;
  }

  const expandedPattern = expandPathPattern(rule.pattern);
  const resolvedPath = isAbsolute(filePath)
    ? filePath
    : resolve(getProjectRoot() || process.cwd(), filePath);

  return globMatch(expandedPattern, resolvedPath.replace(/\\/g, '/'));
}

// ========== Main export ==========

/**
 * Check if a tool invocation is allowed/denied by settings.json permissions.
 *
 * @param {string} toolName
 * @param {Object} input
 * @returns {'allow' | 'deny' | 'none'}
 */
export function checkSettingsPermission(toolName, input) {
  try {
    const globalRules = getGlobalRules();
    const projectRules = getProjectRules();

    const allDenyRuleList = [...globalRules.deny, ...projectRules.deny];
    const allAllowRuleList = [...globalRules.allow, ...projectRules.allow];

    // deny takes priority
    for (const rule of allDenyRuleList) {
      if (matchRule(rule, toolName, input)) {
        debugLog('SETTINGS_PERM', `deny rule matched: ${rule.raw}`, { toolName, input });
        return 'deny';
      }
    }

    // then check allow
    for (const rule of allAllowRuleList) {
      if (matchRule(rule, toolName, input)) {
        debugLog('SETTINGS_PERM', `allow rule matched: ${rule.raw}`, { toolName, input });
        return 'allow';
      }
    }

    return 'none';
  } catch (error) {
    debugLog('SETTINGS_PERM', `check permission fail: ${error.message}`);
    // fail open to interactive permission
    return 'none';
  }
}
