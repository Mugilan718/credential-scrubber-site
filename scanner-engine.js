/**
 * scanner-engine.js
 * Client-side credential detection engine - runs entirely in the browser.
 * No network requests. No file ever leaves the user's device.
 *
 * Ported from the tested Python engine.py, covering:
 * - key-name matching (always redacts, overrides placeholder allow-list)
 * - value-pattern matching (IPs, connection strings, tokens, JWTs, etc.)
 * - entropy detection (tuned to exclude identifier-style strings)
 * - placeholder allow-list (only suppresses value/entropy matches)
 * - multi-line concatenated secrets: Python parenthesized string
 *   concatenation, and Java/JavaScript/C# "+"-operator concatenation
 *   (both leading-+ and trailing-+ styles) - see scanMultilinePython()/
 *   scanMultilinePlus() below. Matches the desktop app's coverage exactly:
 *   Go is not covered (same known limitation as engine.py), and neither
 *   is a multi-line JS/TS template literal.
 * - placeholder mode: an opt-in alternative to the shared MASK where every
 *   finding instead gets a deterministic, typed placeholder like
 *   <PASSWORD_1>/<API_KEY_1> - see PlaceholderRegistry and scanFiles()'s
 *   `options.placeholderMode` below.
 * - ignore-list reconciliation (hashValue()/applyIgnores()): same
 *   hash-verification approach as the desktop app's check_ignore() - a
 *   finding whose value's hash matches a stored ignore is suppressed; one
 *   whose value has since changed reappears, flagged, rather than being
 *   silently suppressed. Persistence itself (IndexedDB) lives in
 *   storage.js, not here - this file only contains the pure, storage-
 *   independent reconciliation logic, so it stays testable under plain
 *   Node with no browser/IndexedDB involved.
 * - config-line shapes beyond bareword "key=value"/"key: value": JSON
 *   quoted keys, XML element text, and XML/.config attribute pairs
 *   (<add key=".." value=".."/>) - see findKeyValue()/KV_PATTERN_CONFIGS
 *   below, ported from engine.py's _KV_JSON_KEY/_KV_XML_ELEMENT/
 *   _KV_XML_ATTR_PAIR. Redaction now reconstructs the line from the exact
 *   text before/after the value's own span (quoteWrap()) instead of a
 *   whole-line substring search, which also fixed a latent bug: a quoted
 *   value's quotes are now preserved in the output (previously stripped
 *   for every format, which silently produced invalid JSON for a redacted
 *   JSON string value).
 *
 * Known limitations (not yet ported - out of scope so far, not fixed by
 * omission):
 * - YAML's "force_quote" nuance (quoteWrap() here has no equivalent) -
 *   engine.py double-quotes an unquoted YAML scalar's mask because a bare
 *   leading "*" is YAML's alias-reference syntax; this file does not yet
 *   apply that same force-quoting.
 * - No parser-backed JSON/XML handling - these are still regex/line-based,
 *   same as engine.py, with the same inherent edge cases that implies.
 */

const MASK = "***REDACTED***";

const CONFIG_EXTENSIONS = new Set([".properties", ".yml", ".yaml", ".json", ".xml", ".ini", ".conf", ".cfg", ".config"]);
const CODE_EXTENSIONS = {
  ".java": "java", ".py": "python",
  ".js": "javascript", ".jsx": "javascript", ".ts": "javascript", ".tsx": "javascript",
  ".go": "go", ".cs": "csharp",
};
const CONFIG_FILENAMES = new Set([".env"]);
const SKIP_DIRS = new Set([".git", "node_modules", "__pycache__", ".venv", "venv", "target", "dist", "build", ".idea", ".vscode"]);

// ---------------------------------------------------------------------
// Shared ruleset loading. `rules-data.js` is generated FROM
// rules_default.yaml by the Python project's export_rules.py - the single
// source of truth for what counts as a key pattern, value pattern, code
// pattern, and placeholder-allowlist entry. When it's available (loaded as
// a <script> before this file in a browser, exposing `window.RULES`; or
// via Node's `require()` when this file is loaded directly, e.g. by the
// test script), every rule category below is built from it, so the two
// engines can never silently drift apart the way a hand-duplicated copy
// could. The FALLBACK_* constants further down exist only for resilience
// if rules-data.js is ever missing or fails to load - they are a snapshot,
// not the intended steady-state source, and won't automatically pick up a
// future rules_default.yaml change the way the live data path does.
// ---------------------------------------------------------------------
const SHARED_RULES = (function () {
  if (typeof window !== "undefined" && window.RULES) return window.RULES;
  if (typeof require === "function") {
    try {
      return require("./rules-data.js");
    } catch (e) {
      return null;
    }
  }
  return null;
})();

// Data-driven pattern sources (from rules_default.yaml via export_rules.py)
// may include a Python-style inline `(?i)` case-insensitive flag, which is
// not valid regex syntax in JavaScript. Every pattern in this engine is
// already matched case-insensitively regardless, so this strips it and
// applies the "i" flag externally instead.
function compileSharedPattern(source) {
  const cleaned = source.startsWith("(?i)") ? source.slice(4) : source;
  return new RegExp(cleaned, "i");
}

// One side of a strict (config-key-style) boundary check - mirrors
// engine.py's _strict_boundary_ok(): only a non-alphanumeric char (or no
// char at all) counts as a separator, no camelCase allowance, since
// config/env keys are conventionally snake_case/dot/kebab-case (e.g.
// "db_port"/"db.port" should match a "port" rule but "support" should not).
function strictBoundaryOk(adjacentChar) {
  return adjacentChar == null || !/[A-Za-z0-9]/.test(adjacentChar);
}

function keyPatternMatchesStrict(source, text) {
  const re = new RegExp(source, "gi");
  let m;
  while ((m = re.exec(text)) !== null) {
    if (m[0].length === 0) { re.lastIndex++; continue; }
    const start = m.index;
    const end = start + m[0].length;
    const prevChar = start > 0 ? text[start - 1] : null;
    const nextChar = end < text.length ? text[end] : null;
    if (strictBoundaryOk(prevChar) && strictBoundaryOk(nextChar)) return true;
  }
  return false;
}

// Last-known-good snapshot of rules_default.yaml, used only if rules-data.js
// is missing/fails to load. Keep in sync manually if this ever needs to be
// relied on for long; the live path above is what should normally be used.
const FALLBACK_KEY_PATTERN_SOURCES = [
  "password", "passwd", "pwd", "secret", "token", "api[_-]?key", "apikey",
  "access[_-]?key", "private[_-]?key", "client[_-]?secret", "auth",
  "credential", "connection[_-]?string", "conn[_-]?str", "jdbc",
  "datasource\\.url", "db\\.url", "db\\.host", "db\\.password", "db\\.username",
  "host", "hostname", "ip[_-]?address", "endpoint", "url", "uri", "ssn",
  "encryption[_-]?key", "signing[_-]?key", "session[_-]?key", "cert",
  "keystore", "truststore",
];

const FALLBACK_VALUE_PATTERNS = [
  ["ipv4_address", /\b(?:\d{1,3}\.){3}\d{1,3}\b/i],
  ["ipv6_address", /\b([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/i],
  ["url_with_credentials", /[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s:/@]+:[^\s:/@]+@[^\s"']+/i],
  ["generic_url", /(https?|ftp|jdbc:[a-z]+|mongodb(\+srv)?|redis|amqp):\/\/[^\s"']+/i],
  ["aws_access_key_id", /\bAKIA[0-9A-Z]{16}\b/],
  ["aws_secret_key_assignment", /aws_secret_access_key["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}/i],
  ["github_token", /\bgh[pousr]_[A-Za-z0-9]{36}\b/],
  ["slack_token", /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/],
  ["jwt_token", /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/],
  ["bearer_token", /bearer\s+[A-Za-z0-9\-._~+/]+=*/i],
  ["private_key_block", /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----/],
  ["email_address", /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/],
];

const FALLBACK_CODE_PATTERNS = {
  java: [/(?:String|final\s+String)\s+\w*(?:password|secret|token|apikey|api_key|key|credential|auth)\w*\s*=\s*"([^"]*)"/i],
  python: [/\w*(?:password|secret|token|apikey|api_key|key|credential|auth)\w*\s*=\s*["']([^"']*)["']/i],
  javascript: [/(?:const|let|var)\s+\w*(?:password|secret|token|apikey|api_key|key|credential|auth)\w*\s*(?::\s*[\w<>|]+\s*)?=\s*[`"']([^`"']*)[`"']/i],
  go: [/\w*(?:password|secret|token|apikey|api_key|key|credential|auth)\w*\s*:?=\s*"([^"]*)"/i],
  csharp: [/(?:string|var)\s+\w*(?:password|secret|token|apikey|api_key|key|credential|auth)\w*\s*=\s*"([^"]*)"/i],
};

const FALLBACK_PLACEHOLDER_ALLOWLIST = [
  "changeme", "change_me", "your_api_key_here", "your-api-key-here", "yourapikeyhere",
  "example", "dummy", "placeholder", "xxxxxxxx", "test123", "localhost", "127.0.0.1",
  "0.0.0.0", "none", "null", "n/a", "todo", "fixme", "insert_secret_here",
];

// BASE_* below is the shared ruleset exactly as rules-data.js/window.RULES
// (or the fallback snapshot) provides it - a plain, immutable snapshot,
// never written to by anything in this file. Phase 4's local rule editor
// layers a per-browser override on TOP of this at scan time (see
// computeEffectiveKeyPatterns()/computeEffectivePlaceholderAllowlist() and
// scanFiles()'s `options.ruleOverrides` below) without ever touching these
// constants - editing your own session's rules can never drift the shared
// base rules-data.js was synced from.
const BASE_KEY_PATTERN_SOURCES = (SHARED_RULES && SHARED_RULES.key_patterns) || FALLBACK_KEY_PATTERN_SOURCES;
const BASE_PLACEHOLDER_ALLOWLIST_LIST = (SHARED_RULES && SHARED_RULES.placeholder_allowlist) || FALLBACK_PLACEHOLDER_ALLOWLIST;

const VALUE_PATTERNS = (SHARED_RULES && SHARED_RULES.value_patterns)
  ? SHARED_RULES.value_patterns.map((vp) => [vp.name, compileSharedPattern(vp.regex)])
  : FALLBACK_VALUE_PATTERNS;

const CODE_PATTERNS = (SHARED_RULES && SHARED_RULES.code_patterns)
  ? Object.fromEntries(
      Object.entries(SHARED_RULES.code_patterns).map(([lang, patterns]) => [
        lang, patterns.map(compileSharedPattern),
      ])
    )
  : FALLBACK_CODE_PATTERNS;

// The lists detection actually consults. Equal to the base by default;
// temporarily reassigned (never mutated in place - always to a brand-new
// array/Set) to an override-merged view for the duration of a single
// scanFiles() call, then restored - see scanFiles()'s try/finally below.
// This file is single-threaded/synchronous end to end (no `await` appears
// anywhere between the reassignment and its restoration), so there is no
// reentrancy hazard today; if scanFiles() ever became async or callable
// concurrently, this pattern would need to change to explicit parameter
// threading instead.
let KEY_PATTERN_SOURCES = BASE_KEY_PATTERN_SOURCES;
let PLACEHOLDER_ALLOWLIST = new Set(BASE_PLACEHOLDER_ALLOWLIST_LIST);

// ---------------------------------------------------------------------
// Local rule overrides (Phase 4) - a per-browser-session layer on top of
// BASE_KEY_PATTERN_SOURCES/BASE_PLACEHOLDER_ALLOWLIST_LIST, never a
// modification of them. `overrides` is a plain object (exactly what
// storage.js's getRuleOverrides() returns):
//   { keyPatternsAdded, keyPatternsRemoved,
//     placeholderAllowlistAdded, placeholderAllowlistRemoved }
// Both functions always return a BRAND-NEW array - the base array/Set
// itself is only ever read, never spliced/pushed/deleted into.
// ---------------------------------------------------------------------

function computeEffectiveKeyPatterns(overrides) {
  if (!overrides) return BASE_KEY_PATTERN_SOURCES.slice();
  const removed = new Set(overrides.keyPatternsRemoved || []);
  const added = overrides.keyPatternsAdded || [];
  return BASE_KEY_PATTERN_SOURCES.filter((p) => !removed.has(p)).concat(added);
}

function computeEffectivePlaceholderAllowlist(overrides) {
  if (!overrides) return BASE_PLACEHOLDER_ALLOWLIST_LIST.slice();
  const removed = new Set((overrides.placeholderAllowlistRemoved || []).map((v) => v.toLowerCase()));
  const added = (overrides.placeholderAllowlistAdded || []).map((v) => v.toLowerCase());
  return BASE_PLACEHOLDER_ALLOWLIST_LIST.filter((p) => !removed.has(p.toLowerCase())).concat(added);
}

// For tests (and anything else that wants to prove the base was never
// touched): a snapshot of the shared base lists, independent of whatever
// KEY_PATTERN_SOURCES/PLACEHOLDER_ALLOWLIST currently point at. Safe to
// call any time - even mid-scan, this always reads the untouched
// BASE_* constants, never the temporarily-swapped active ones.
function getBaseRuleSnapshot() {
  return {
    keyPatternSources: BASE_KEY_PATTERN_SOURCES.slice(),
    placeholderAllowlist: BASE_PLACEHOLDER_ALLOWLIST_LIST.slice(),
  };
}

// ---------------------------------------------------------------------
// Placeholder mode - ported from engine.py's PlaceholderRegistry /
// category_for_*() / _most_specific_category(). Opt-in alternative to the
// shared MASK: every function below accepts an optional `registry`
// (a PlaceholderRegistry instance) as its last parameter - null/omitted
// means exactly today's MASK behavior, unchanged byte-for-byte.
// ---------------------------------------------------------------------

const DEFAULT_CATEGORY = "GENERIC_SECRET";

// Keyed by the exact raw key_pattern string, mirroring engine.py's
// KEY_PATTERN_CATEGORY. A pattern not listed here (e.g. a future addition
// to rules_default.yaml not yet mapped) falls back to DEFAULT_CATEGORY
// rather than throwing - this table is an aid, not a schema.
const KEY_PATTERN_CATEGORY = {
  "password": "PASSWORD", "passwd": "PASSWORD", "pwd": "PASSWORD",
  "secret": "GENERIC_SECRET", "token": "ACCESS_TOKEN",
  "api[_-]?key": "API_KEY", "apikey": "API_KEY", "access[_-]?key": "API_KEY",
  "private[_-]?key": "PRIVATE_KEY", "client[_-]?secret": "API_KEY",
  "auth": "ACCESS_TOKEN", "credential": "GENERIC_SECRET",
  "connection[_-]?string": "CONNECTION_STRING", "conn[_-]?str": "CONNECTION_STRING",
  "jdbc": "CONNECTION_STRING", "datasource\\.url": "URL", "db\\.url": "URL",
  "db\\.host": "URL", "db\\.password": "PASSWORD", "db\\.username": "GENERIC_SECRET",
  "host": "URL", "hostname": "URL", "ip[_-]?address": "URL", "endpoint": "URL",
  "url": "URL", "uri": "URL", "ssn": "GENERIC_SECRET",
  "encryption[_-]?key": "PRIVATE_KEY", "signing[_-]?key": "PRIVATE_KEY",
  "session[_-]?key": "GENERIC_SECRET", "cert": "GENERIC_SECRET",
  "keystore": "GENERIC_SECRET", "truststore": "GENERIC_SECRET",
};

// Keyed by value_pattern name; "high_entropy" is the synthetic reason
// string used when only the entropy heuristic fired (not a real
// value_pattern), included here for the same lookup.
const VALUE_PATTERN_CATEGORY = {
  "ipv4_address": "URL", "ipv6_address": "URL", "url_with_credentials": "URL",
  "generic_url": "URL", "aws_access_key_id": "API_KEY",
  "aws_secret_key_assignment": "API_KEY", "github_token": "ACCESS_TOKEN",
  "slack_token": "ACCESS_TOKEN", "jwt_token": "ACCESS_TOKEN",
  "bearer_token": "ACCESS_TOKEN", "private_key_block": "PRIVATE_KEY",
  "email_address": "GENERIC_SECRET", "high_entropy": "GENERIC_SECRET",
};

// Keyed by the suspicious keyword found in a code_pattern's matched
// variable/field name - see extractCodeKeyword(). Checked in this specific
// order (most-specific first) so e.g. "apiKey" resolves via "apikey"
// (API_KEY) rather than falling through to the more generic bare "key"
// (GENERIC_SECRET), since "apikey" itself contains "key" as a substring.
const CODE_KEYWORD_ORDER = ["password", "apikey", "api_key", "credential", "auth", "secret", "token", "key"];
const CODE_KEYWORD_CATEGORY = {
  "password": "PASSWORD", "secret": "GENERIC_SECRET", "token": "ACCESS_TOKEN",
  "apikey": "API_KEY", "api_key": "API_KEY", "key": "GENERIC_SECRET",
  "credential": "GENERIC_SECRET", "auth": "ACCESS_TOKEN",
};

function categoryForKeyPattern(source) {
  return KEY_PATTERN_CATEGORY[source] || DEFAULT_CATEGORY;
}
function categoryForValuePattern(name) {
  return VALUE_PATTERN_CATEGORY[name] || DEFAULT_CATEGORY;
}
function extractCodeKeyword(text) {
  const lower = text.toLowerCase();
  for (const kw of CODE_KEYWORD_ORDER) {
    if (lower.includes(kw)) return kw;
  }
  return null;
}
function categoryForCodeKeyword(keyword) {
  if (!keyword) return DEFAULT_CATEGORY;
  return CODE_KEYWORD_CATEGORY[keyword.toLowerCase()] || DEFAULT_CATEGORY;
}

// Some keys match more than one key_pattern (e.g. "client_secret" matches
// both the bare "secret" pattern and the more specific "client[_-]?secret"
// one) - prefer whichever matched pattern maps to a named category over one
// that only falls back to DEFAULT_CATEGORY, so a generic pattern appearing
// earlier in the list doesn't shadow a more specific one appearing later.
function mostSpecificCategory(categories) {
  let fallback = DEFAULT_CATEGORY;
  for (const c of categories) {
    if (c !== DEFAULT_CATEGORY) return c;
    fallback = c;
  }
  return fallback;
}

// Strip one matching pair of surrounding quote characters, if any, so the
// same underlying value is recognized as identical for placeholder
// correlation regardless of which quote style (or none) it happens to be
// written with (e.g. "PF001" and 'PF001' must correlate). Mirrors
// engine.py's _normalize_value_for_identity().
function normalizeValueForIdentity(value) {
  const v = value.replace(/\s+$/, "");
  if (v.length >= 2 && (v[0] === '"' || v[0] === "'") && v[v.length - 1] === v[0]) {
    return v.slice(1, -1);
  }
  return v;
}

const PLACEHOLDER_SHAPE = /<[A-Z_]+_\d+>/;

// True if `text` contains a marker a previous pass already inserted - MASK
// always, plus (only when placeholder mode is active) anything shaped like
// a typed placeholder token - so a later pass doesn't try to re-redact text
// an earlier pass on the same line already replaced. Mirrors engine.py's
// _already_redacted().
function alreadyRedactedText(text, registry) {
  if (text.includes(MASK)) return true;
  if (registry && PLACEHOLDER_SHAPE.test(text)) return true;
  return false;
}

/**
 * Deterministic, typed placeholder assignment for exactly one scanFiles()
 * call. Maps (category, exact_value) -> a stable "<CATEGORY_N>" token, with
 * a separate ordinal counter per category. Two different real values in
 * the same category never collide on one placeholder; the same real value
 * under a different key/variable name (or in a different file within the
 * same scan) always gets the same one.
 *
 * Security: this map is exactly as sensitive as the secrets it indexes. It
 * is never persisted, never logged, and exists only in memory for the
 * lifetime of the scanFiles() call that created it, then is discarded with
 * it. The placeholder text itself is built only from a fixed category name
 * and an integer - never from any character of the original value - so it
 * cannot leak the secret's content, length, prefix, suffix, or provider
 * even if the placeholder text itself were ever exposed. Mirrors
 * engine.py's PlaceholderRegistry exactly.
 */
class PlaceholderRegistry {
  constructor() {
    this._map = new Map();
    this._counters = new Map();
  }
  getOrCreate(category, value) {
    const key = `${category}\u0000${value}`;
    let token = this._map.get(key);
    if (token === undefined) {
      const n = (this._counters.get(category) || 0) + 1;
      this._counters.set(category, n);
      token = `<${category}_${n}>`;
      this._map.set(key, token);
    }
    return token;
  }
}

// One replacement string per multiline fragment, in order. MASK mode
// (registry is null - today's exact, unchanged default): every fragment
// individually gets MASK. Placeholder mode: the whole reconstructed value
// is one entity, so it gets exactly one placeholder - assigned to the
// FIRST fragment - with every later fragment's span emptied, rather than
// each fragment getting its own (misleadingly implying separate secrets).
function multilineReplacements(registry, category, joined, fragmentCount) {
  if (registry) {
    const full = registry.getOrCreate(category, joined);
    return [full, ...Array(fragmentCount - 1).fill("")];
  }
  return Array(fragmentCount).fill(MASK);
}

function isPlaceholder(value) {
  const v = value.trim().replace(/^["']|["']$/g, "").toLowerCase();
  return PLACEHOLDER_ALLOWLIST.has(v);
}

function shannonEntropy(s) {
  if (!s) return 0;
  const freq = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  const len = s.length;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function looksHighEntropy(value, minLength = 20, minEntropy = 3.5) {
  const v = value.trim().replace(/^["']|["']$/g, "");
  if (v.length < minLength) return false;
  // Exemption: plain words joined only by underscore/hyphen/slash/colon/dot
  // (snake_case, kebab-case, Docker-style repo/name:tag) - not randomness.
  if (/^[A-Za-z\s_\-/:.]+$/.test(v)) return false;
  return shannonEntropy(v) >= minEntropy;
}

// Config lines come in more shapes than "key: value"/"key=value" - JSON
// quoted keys, XML elements, and .config-style <add key=".." value=".."/>
// pairs all hold a key and a value too, just with different surrounding
// syntax. Ported from engine.py's _KV_XML_ATTR_PAIR/_KV_XML_ELEMENT/
// _KV_JSON_KEY/_KV_BAREWORD, tried in the same order (most structurally
// specific first; order barely matters in practice since they're mutually
// exclusive by leading character - "<", '"', or a bareword char).
//
// Each pattern's `build` function returns [beforeValue, afterValue] - the
// exact original-line text immediately before/after the value's own span -
// so redactConfigLine() can reconstruct the line as
// beforeValue + wrappedReplacement + afterValue instead of a fragile
// whole-line substring search/replace (which can hit an earlier, unrelated
// occurrence of the same text, e.g. "secret_key=secret").
const KV_XML_ATTR_PAIR = /^(?<prefix>\s*<[\w:.-]+\s+[^>]*?\bkey\s*=\s*["'])(?<key>[^"']+)(?<mid>["'][^>]*?\bvalue\s*=\s*["'])(?<value>[^"']*)(?<suffix>["'].*)$/i;
const KV_XML_ELEMENT = /^(?<prefix>\s*<(?<key>[A-Za-z_][\w.-]*)(?:\s[^>]*)?>)(?<value>[^<]*)(?<suffix><\/\k<key>>\s*)$/;
const KV_JSON_KEY = /^(?<prefix>\s*"(?<key>[^"]+)"\s*:\s*)(?<value>.*?)(?<suffix>,?\s*)$/;
const KV_BAREWORD = /^(?<prefix>\s*(?<key>[A-Za-z0-9_.\-\[\]]+)\s*[:=]\s*)(?<value>.*)$/;

const KV_PATTERN_CONFIGS = [
  { pattern: KV_XML_ATTR_PAIR, build: (g) => [g.prefix + g.key + g.mid, g.suffix] },
  { pattern: KV_XML_ELEMENT, build: (g) => [g.prefix, g.suffix] },
  { pattern: KV_JSON_KEY, build: (g) => [g.prefix, g.suffix] },
  { pattern: KV_BAREWORD, build: (g) => [g.prefix, ""] },
];

// A bare YAML block-scalar indicator ("|", ">", with an optional chomping
// "+"/"-" and/or explicit indentation digit, e.g. "|-", ">+4") - like a
// JSON "{"/"[" opener, this isn't a redactable leaf value; the real content
// is the indented lines that follow, which this function never sees as
// this key's value at all.
const YAML_BLOCK_SCALAR = /^[|>][+-]?\d*$/;

function isNonRedactableValueShape(stripped) {
  return stripped === "{" || stripped === "[" || YAML_BLOCK_SCALAR.test(stripped);
}

/**
 * Extract (key, value, beforeValue, afterValue) from a config line, or
 * (null, null, null, null) if it doesn't look like any recognized shape
 * (redactValuePatternsOnly is used instead in that case).
 */
function findKeyValue(line) {
  for (const { pattern, build } of KV_PATTERN_CONFIGS) {
    const m = pattern.exec(line);
    if (!m) continue;
    const value = m.groups.value;
    if (isNonRedactableValueShape(value.trim())) continue;
    const [beforeValue, afterValue] = build(m.groups);
    return [m.groups.key, value, beforeValue, afterValue];
  }
  return [null, null, null, null];
}

// Wrap `replacementText` (MASK or a placeholder token) in the same quote
// character `value`'s original span used, if any - so a JSON/XML value
// stays syntactically valid after redaction (an unquoted bare token where
// a quoted string used to be would corrupt JSON) and other formats keep
// their original quoting style. Mirrors engine.py's _quote_wrap() (minus
// YAML's force_quote nuance, a separate, pre-existing, not-yet-ported gap
// - see the "Known limitations" note in this file's own module comment).
function quoteWrap(value, replacementText) {
  const v = value.replace(/\s+$/, "");
  if (v.length >= 2 && (v[0] === '"' || v[0] === "'") && v[v.length - 1] === v[0]) {
    return v[0] + replacementText + v[0];
  }
  return replacementText;
}

function redactConfigLine(line, lineNo, filename, reportEntries, registry = null) {
  const [key, value, beforeValue, afterValue] = findKeyValue(line);
  if (key === null) return redactValuePatternsOnly(line, lineNo, filename, reportEntries, registry);
  if (value.trim() === "") return line;

  const matchedPatterns = KEY_PATTERN_SOURCES.filter((src) => keyPatternMatchesStrict(src, key));

  if (matchedPatterns.length > 0) {
    const replacement = registry
      ? registry.getOrCreate(mostSpecificCategory(matchedPatterns.map(categoryForKeyPattern)), normalizeValueForIdentity(value))
      : MASK;
    reportEntries.push({ file: filename, line: lineNo, key, rule: "key_name_match", before: value, after: replacement });
    return beforeValue + quoteWrap(value, replacement) + afterValue;
  }

  if (isPlaceholder(value)) return line;

  let valueMatchedName = null;
  for (const [name, pattern] of VALUE_PATTERNS) {
    if (pattern.test(value)) { valueMatchedName = name; break; }
  }
  const entropyFlag = looksHighEntropy(value);

  if (valueMatchedName || entropyFlag) {
    const reason = valueMatchedName || "high_entropy";
    const replacement = registry
      ? registry.getOrCreate(categoryForValuePattern(reason), normalizeValueForIdentity(value))
      : MASK;
    reportEntries.push({ file: filename, line: lineNo, key, rule: reason, before: value, after: replacement });
    return beforeValue + quoteWrap(value, replacement) + afterValue;
  }

  return line;
}

function redactValuePatternsOnly(line, lineNo, filename, reportEntries, registry = null) {
  let modified = line;
  for (const [name, pattern] of VALUE_PATTERNS) {
    const m = modified.match(pattern);
    if (m) {
      if (isPlaceholder(m[0])) continue;
      const replacement = registry ? registry.getOrCreate(categoryForValuePattern(name), m[0]) : MASK;
      reportEntries.push({ file: filename, line: lineNo, key: null, rule: name, before: m[0], after: replacement });
      modified = modified.replace(pattern, replacement);
    }
  }
  return modified;
}

function redactCodeLine(line, lang, lineNo, filename, reportEntries, registry = null) {
  let modified = line;
  const patterns = CODE_PATTERNS[lang] || [];

  for (const pattern of patterns) {
    const m = modified.match(pattern);
    if (m && m[1] !== undefined && m[1].trim() !== "") {
      const literalValue = m[1];
      const start = m.index + m[0].indexOf(m[1]);
      let replacement;
      if (registry) {
        const precedingText = m[0].slice(0, m[0].indexOf(m[1]));
        replacement = registry.getOrCreate(categoryForCodeKeyword(extractCodeKeyword(precedingText)), literalValue);
      } else {
        replacement = MASK;
      }
      modified = modified.slice(0, start) + replacement + modified.slice(start + literalValue.length);
      reportEntries.push({ file: filename, line: lineNo, key: "code_literal", rule: "code_variable_pattern", before: literalValue, after: replacement });
    }
  }

  for (const [name, pattern] of VALUE_PATTERNS) {
    const m = modified.match(pattern);
    if (m && !alreadyRedactedText(modified.slice(m.index, m.index + m[0].length), registry)) {
      if (isPlaceholder(m[0])) continue;
      const replacement = registry ? registry.getOrCreate(categoryForValuePattern(name), m[0]) : MASK;
      reportEntries.push({ file: filename, line: lineNo, key: null, rule: name, before: m[0], after: replacement });
      modified = modified.replace(pattern, replacement);
    }
  }

  return modified;
}

// ---------------------------------------------------------------------
// Multi-line concatenation handling - ported from engine.py's
// scan_multiline_python()/scan_multiline_plus() (see _PY_*/_PLUS_* regexes
// there). MASK-mode only for now (every fragment gets its own MASK) -
// typed-placeholder mode for multiline is a later phase.
// ---------------------------------------------------------------------

const PLUS_CONCAT_LANGS = new Set(["java", "javascript", "csharp"]); // matches engine.py's PLUS_CONCAT_LANGS - Go is intentionally not covered

const PY_ASSIGN_OPEN = /^\s*([A-Za-z_]\w*)\s*=\s*\(\s*$/;
const PY_FRAGMENT = /^\s*["']([^"']*)["']\s*$/;
const PY_CLOSE = /^\s*\)\s*$/;

// Matches the FIRST line of a concatenation: `... var = "frag"` with an
// OPTIONAL trailing `+` (covers both the "trailing +" and "leading +" styles).
const PLUS_ASSIGN_START = /^(?:\s*(?:private|public|protected|static|final|readonly|const|let|var)\s+)*[\w<>\[\],\s]*?(\w+)\s*=\s*["']([^"']*)["']\s*(\+\s*)?$/;
// Continuation, "leading +" style:      + "frag"      or      + "frag";
const PLUS_CONT_LEADING = /^\s*\+\s*["']([^"']*)["']\s*(;)?\s*$/;
// Continuation, "trailing +" style:      "frag" +      or      "frag";
const PLUS_CONT_TRAILING = /^\s*["']([^"']*)["']\s*(\+)?\s*(;)?\s*$/;

// KEY_PATTERN_SOURCES (data-driven, defined near the top of this file
// alongside SHARED_RULES) is reused here too - the same raw pattern list
// now drives both the strict-boundary config-key check above and this
// camelCase-aware variable-name check, so there is exactly one place the
// two could ever drift apart: rules_default.yaml itself. Mirrors
// engine.py's find_key_matches()/key_pattern_matches(camel_aware=True).

function isAlpha(ch) { return /[A-Za-z]/.test(ch); }
function isLower(ch) { return /[a-z]/.test(ch); }

// One side of a camelCase-aware identifier-boundary check - mirrors
// engine.py's _char_boundary_ok(): a valid boundary is no char at all, a
// non-letter (digit/underscore/etc.), or a letter whose case differs from
// the matched keyword's edge char (a camelCase transition, e.g. the "i"/"K"
// join in "apiKey").
function charBoundaryOk(adjacentChar, keywordChar) {
  if (adjacentChar == null) return true;
  if (!isAlpha(adjacentChar)) return true;
  return isLower(adjacentChar) !== isLower(keywordChar);
}

function keyPatternMatchesCamel(source, text) {
  const re = new RegExp(source, "gi");
  let m;
  while ((m = re.exec(text)) !== null) {
    if (m[0].length === 0) { re.lastIndex++; continue; }
    const start = m.index;
    const end = start + m[0].length;
    const prevChar = start > 0 ? text[start - 1] : null;
    const nextChar = end < text.length ? text[end] : null;
    if (charBoundaryOk(prevChar, text[start]) && charBoundaryOk(nextChar, text[end - 1])) {
      return true;
    }
  }
  return false;
}

// The list of every matching key pattern (possibly empty), for callers
// that need to resolve a placeholder category via categoryForKeyPattern(),
// preferring the most specific match when more than one matches - see
// mostSpecificCategory(). findKeyMatches() below stays a plain boolean for
// existing boolean-context callers (an empty ARRAY is truthy in
// JavaScript, unlike Python, so this distinction matters here).
function matchedKeyPatterns(name) {
  return KEY_PATTERN_SOURCES.filter((src) => keyPatternMatchesCamel(src, name));
}

function findKeyMatches(name) {
  return matchedKeyPatterns(name).length > 0;
}

// Shared tail-end of both multiline scanners below: given the reconstructed
// value and where its fragments live, decide whether to redact and, if so,
// mask (or placeholder-ize) each fragment's quoted span in place and record
// one report entry per fragment - mirrors engine.py's shared
// key_hit/value_hit/entropy_hit gate.
function maybeRedactMultiline(varName, joined, fragIndices, fragments, lines, filename, reportEntries, registry = null) {
  const keyMatches = matchedKeyPatterns(varName);
  const keyHit = keyMatches.length > 0;
  let valueHit = null;
  for (const [name, pattern] of VALUE_PATTERNS) {
    if (pattern.test(joined)) { valueHit = name; break; }
  }
  const entropyHit = looksHighEntropy(joined);
  if (!(keyHit || valueHit || entropyHit)) return;
  if (!keyHit && isPlaceholder(joined)) return;

  const reason = keyHit ? "key_name_match" : (valueHit || "high_entropy");
  const rule = `multiline_concat_${reason}`;
  const category = keyHit
    ? mostSpecificCategory(keyMatches.map(categoryForKeyPattern))
    : categoryForValuePattern(valueHit || "high_entropy");
  const replacements = multilineReplacements(registry, category, joined, fragments.length);

  fragIndices.forEach((idx, k) => {
    const frag = fragments[k];
    const replacement = replacements[k];
    lines[idx] = lines[idx].replace(/(["'])[^"']*\1/, (whole, q) => q + replacement + q);
    reportEntries.push({ file: filename, line: idx + 1, key: varName, rule, before: frag, after: replacement });
  });
}

/** Detect and redact `var = (\n "frag" \n "frag" \n)` across physical lines. */
function scanMultilinePython(lines, filename, reportEntries, registry = null) {
  const n = lines.length;
  let i = 0;
  while (i < n) {
    const m = PY_ASSIGN_OPEN.exec(lines[i]);
    if (m) {
      const varName = m[1];
      const fragIndices = [];
      const fragments = [];
      let j = i + 1;
      let fm;
      while (j < n && (fm = PY_FRAGMENT.exec(lines[j]))) {
        fragments.push(fm[1]);
        fragIndices.push(j);
        j++;
      }
      if (j < n && PY_CLOSE.test(lines[j]) && fragments.length > 0) {
        const joined = fragments.join("");
        maybeRedactMultiline(varName, joined, fragIndices, fragments, lines, filename, reportEntries, registry);
      }
    }
    i++;
  }
}

/**
 * Detect and redact string concatenation spanning multiple physical lines,
 * in either style:
 *     var = "frag" +          var = "frag"
 *         "frag" +                + "frag"
 *         "frag";                 + "frag";
 * Only redacts if the chain is properly terminated with ';' - a chain that
 * trails off without a terminator is left untouched rather than guessed at.
 */
function scanMultilinePlus(lines, filename, reportEntries, registry = null) {
  const n = lines.length;
  let i = 0;
  while (i < n) {
    const m = PLUS_ASSIGN_START.exec(lines[i]);
    if (m) {
      const varName = m[1];
      const firstFrag = m[2];
      const hadTrailingPlus = !!m[3];
      const fragments = [firstFrag];
      const fragIndices = [i];
      let j = i + 1;
      let terminated = false;

      if (hadTrailingPlus) {
        while (j < n) {
          const cont = PLUS_CONT_TRAILING.exec(lines[j]);
          if (!cont) break;
          fragments.push(cont[1]);
          fragIndices.push(j);
          j++;
          if (cont[3]) { terminated = true; break; }
          if (!cont[2]) break;
        }
      } else if (j < n && PLUS_CONT_LEADING.test(lines[j])) {
        while (j < n) {
          const cont = PLUS_CONT_LEADING.exec(lines[j]);
          if (!cont) break;
          fragments.push(cont[1]);
          fragIndices.push(j);
          j++;
          if (cont[2]) { terminated = true; break; }
        }
      }

      if (fragments.length > 1 && terminated) {
        const joined = fragments.join("");
        maybeRedactMultiline(varName, joined, fragIndices, fragments, lines, filename, reportEntries, registry);
      }
    }
    i++;
  }
}

function classifyFile(path) {
  const name = path.split("/").pop();
  if (CONFIG_FILENAMES.has(name) || name.startsWith(".env.")) return "config";
  const dotIdx = name.lastIndexOf(".");
  const ext = dotIdx >= 0 ? name.slice(dotIdx).toLowerCase() : "";
  if (CONFIG_EXTENSIONS.has(ext)) return "config";
  if (CODE_EXTENSIONS[ext]) return `code:${CODE_EXTENSIONS[ext]}`;
  return null;
}

/**
 * Scan a list of {path, content} file objects entirely in-memory.
 * `options.placeholderMode`: opt-in, defaults to false/undefined - false
 * preserves today's behavior exactly (every finding masked with the shared
 * MASK constant). true redacts with deterministic, typed placeholders
 * instead, via one PlaceholderRegistry shared across every file in this
 * one call - the same real value, detected as the same category, always
 * gets the same "<CATEGORY_N>" token anywhere in this one scan; different
 * values never collide on one token. The registry lives only for the
 * duration of this function call and is never returned or persisted.
 * `options.ruleOverrides`: opt-in, defaults to null - a per-browser-session
 * override layered on top of the shared base key_patterns/
 * placeholder_allowlist for the duration of THIS call only (see
 * computeEffectiveKeyPatterns()/computeEffectivePlaceholderAllowlist()
 * above). The base rules-data.js/window.RULES data is never modified,
 * regardless of what's passed here - always restored before this function
 * returns, even if it throws.
 * Returns { sanitizedFiles: [{path, content}], reportEntries: [...] }
 */
function scanFiles(files, options = {}) {
  const reportEntries = [];
  const sanitizedFiles = [];
  const registry = options.placeholderMode ? new PlaceholderRegistry() : null;

  const savedKeyPatternSources = KEY_PATTERN_SOURCES;
  const savedPlaceholderAllowlist = PLACEHOLDER_ALLOWLIST;
  if (options.ruleOverrides) {
    KEY_PATTERN_SOURCES = computeEffectiveKeyPatterns(options.ruleOverrides);
    PLACEHOLDER_ALLOWLIST = new Set(computeEffectivePlaceholderAllowlist(options.ruleOverrides));
  }

  try {
    for (const file of files) {
      const parts = file.path.split("/");
      if (parts.some((p) => SKIP_DIRS.has(p))) continue;

      const classification = classifyFile(file.path);
      const lines = file.content.split(/\r?\n/);

      if (classification === "config") {
        const out = lines.map((l, i) => redactConfigLine(l, i + 1, file.path, reportEntries, registry));
        sanitizedFiles.push({ path: file.path, content: out.join("\n") });
      } else if (classification && classification.startsWith("code:")) {
        const lang = classification.split(":")[1];
        if (lang === "python") {
          scanMultilinePython(lines, file.path, reportEntries, registry);
        }
        if (PLUS_CONCAT_LANGS.has(lang)) {
          scanMultilinePlus(lines, file.path, reportEntries, registry);
        }
        const out = lines.map((l, i) => {
          if (alreadyRedactedText(l, registry)) return l; // already redacted by a multiline pass above - don't double-process
          return redactCodeLine(l, lang, i + 1, file.path, reportEntries, registry);
        });
        sanitizedFiles.push({ path: file.path, content: out.join("\n") });
      } else if (classification === null && isLikelyTextFile(file.path)) {
        const out = lines.map((l, i) => redactValuePatternsOnly(l, i + 1, file.path, reportEntries, registry));
        sanitizedFiles.push({ path: file.path, content: out.join("\n") });
      } else {
        sanitizedFiles.push({ path: file.path, content: file.content, binary: true });
      }
    }

    return { sanitizedFiles, reportEntries };
  } finally {
    KEY_PATTERN_SOURCES = savedKeyPatternSources;
    PLACEHOLDER_ALLOWLIST = savedPlaceholderAllowlist;
  }
}

function isLikelyTextFile(path) {
  const binaryExts = [".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".exe", ".dll", ".so", ".woff", ".woff2", ".ttf"];
  const lower = path.toLowerCase();
  return !binaryExts.some((ext) => lower.endsWith(ext));
}

// ---------------------------------------------------------------------
// Folder-filter tree (scan-scope selection) - pure, DOM- and storage-
// independent logic for (a) building a nested tree from a flat list of
// "/"-separated relative file paths, and (b) deriving/mutating
// per-folder checked state from a flat Set of checked LEAF (file) paths.
//
// The checked-paths Set is the single source of truth. A folder's own
// checked/indeterminate/unchecked state is always DERIVED from it by
// walking its descendant files (getNodeCheckState) - never stored
// redundantly on the tree node itself - so tree structure and checked
// state can never drift apart the way two independently-updated copies
// could. Every mutating function here returns a brand-new Set rather
// than mutating the one it was given, matching this file's existing
// "never mutate a caller's state in place" convention (see
// computeEffectiveKeyPatterns()).
// ---------------------------------------------------------------------

/**
 * Build a nested tree from a flat list of relative file paths (e.g.
 * ["src/app.py", "src/utils/helper.py", "README.md"]). Returns the
 * synthetic root node: { type: "folder", name: "", path: "", children }.
 * Folders are created implicitly wherever a file path requires one to
 * exist - there is no separate notion of an "empty folder" (matching how
 * a browser's folder picker/drag-drop only ever reports actual files,
 * never empty directories, so this is never asked to represent one).
 * Children are sorted folders-first, then alphabetically within each
 * type, for deterministic, predictable rendering.
 */
function buildFileTree(paths) {
  const root = { type: "folder", name: "", path: "", children: [] };
  const folderIndex = new Map([["", root]]);

  function getOrCreateFolder(path) {
    if (folderIndex.has(path)) return folderIndex.get(path);
    const lastSlash = path.lastIndexOf("/");
    const parentPath = lastSlash === -1 ? "" : path.slice(0, lastSlash);
    const name = lastSlash === -1 ? path : path.slice(lastSlash + 1);
    const parent = getOrCreateFolder(parentPath);
    const node = { type: "folder", name, path, children: [] };
    parent.children.push(node);
    folderIndex.set(path, node);
    return node;
  }

  for (const filePath of paths) {
    const lastSlash = filePath.lastIndexOf("/");
    const parentPath = lastSlash === -1 ? "" : filePath.slice(0, lastSlash);
    const name = lastSlash === -1 ? filePath : filePath.slice(lastSlash + 1);
    const parent = getOrCreateFolder(parentPath);
    parent.children.push({ type: "file", name, path: filePath });
  }

  sortTreeChildren(root);
  return root;
}

function sortTreeChildren(node) {
  node.children.sort((a, b) => {
    if (a.type !== b.type) return a.type === "folder" ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
  for (const child of node.children) {
    if (child.type === "folder") sortTreeChildren(child);
  }
}

/** Builds a path -> node lookup for the whole tree (root included, keyed by ""). */
function indexFileTree(node, map = new Map()) {
  map.set(node.path, node);
  if (node.type === "folder") {
    for (const child of node.children) indexFileTree(child, map);
  }
  return map;
}

/** All file (leaf) paths under `node`, in tree order. `node` itself may be a file or a folder. */
function collectFilePaths(node, out = []) {
  if (node.type === "file") {
    out.push(node.path);
    return out;
  }
  for (const child of node.children) collectFilePaths(child, out);
  return out;
}

/**
 * "checked" | "unchecked" | "indeterminate" for a file or folder node,
 * derived from how many of its descendant files are in `checkedPaths`.
 * A file node is simply "checked"/"unchecked" (never indeterminate).
 */
function getNodeCheckState(node, checkedPaths) {
  if (node.type === "file") {
    return checkedPaths.has(node.path) ? "checked" : "unchecked";
  }
  const filePaths = collectFilePaths(node);
  if (filePaths.length === 0) return "unchecked";
  let checkedCount = 0;
  for (const p of filePaths) {
    if (checkedPaths.has(p)) checkedCount++;
  }
  if (checkedCount === 0) return "unchecked";
  if (checkedCount === filePaths.length) return "checked";
  return "indeterminate";
}

/**
 * Returns a NEW checked-paths Set with every file under `node` (or just
 * `node` itself, if it's a file) added (checked=true) or removed
 * (checked=false). Checking/unchecking a folder always applies to ALL of
 * its descendants, regardless of their current individual state.
 */
function setNodeChecked(node, checked, checkedPaths) {
  const next = new Set(checkedPaths);
  const filePaths = node.type === "file" ? [node.path] : collectFilePaths(node);
  for (const p of filePaths) {
    if (checked) next.add(p);
    else next.delete(p);
  }
  return next;
}

/** Only the files whose path is in `checkedPaths` - what actually reaches scanFiles(). */
function filterFilesByCheckedPaths(files, checkedPaths) {
  return files.filter((f) => checkedPaths.has(f.path));
}

/**
 * Reapplies a saved folder-filter selection onto a freshly-read list of
 * paths (folder-filter tree, checkpoint 2). `savedAllPaths` and
 * `savedCheckedPaths` come from a previous saveFolderFilter() call;
 * `currentPaths` is every path just read from disk this time.
 *
 * Three cases, decided per current path:
 *   - matched + was checked before   -> stays checked
 *   - matched + was NOT checked before -> stays unchecked (this is why
 *     `savedAllPaths` has to be stored, not just the checked subset - a
 *     path that existed-but-was-unchecked would otherwise be
 *     indistinguishable from a path that's genuinely new)
 *   - not in savedAllPaths (genuinely new, e.g. a file added since the
 *     last scan) -> defaults to checked, same as the "everything checked"
 *     default used the very first time a folder is selected
 *
 * A saved path that no longer exists in `currentPaths` is simply absent
 * from the result - there's nothing to reapply it onto.
 *
 * Pure function: takes plain arrays/iterables of path strings, returns a
 * new Set, never mutates any input.
 */
function reapplySavedSelection(currentPaths, savedAllPaths, savedCheckedPaths) {
  const savedAllSet = new Set(savedAllPaths);
  const savedCheckedSet = new Set(savedCheckedPaths);
  const result = new Set();
  for (const path of currentPaths) {
    if (!savedAllSet.has(path) || savedCheckedSet.has(path)) {
      result.add(path);
    }
  }
  return result;
}

// ---------------------------------------------------------------------
// File System Access API directory walking (Phase 5) - pure, storage-
// and DOM-independent logic for recursively reading a
// FileSystemDirectoryHandle's contents into the same {path, content}
// shape scanFiles() already expects. Kept here (not in scanner-ui.js) so
// it's testable under plain Node with a fake directory-handle tree (see
// tests/fake-fs-access.js) - the real File System Access API itself only
// exists in a browser (Chromium-based ones today) and cannot be exercised
// here; see this project's final summary for what is and isn't covered
// by an actual live test versus this pure-logic unit test.
//
// `dirHandle` need only implement the standard FileSystemDirectoryHandle
// shape used here: an async-iterable `.values()` yielding entries with
// `.kind` ("file"/"directory") and `.name`, and (for files) an async
// `.getFile()` returning a File-like object with `.size` and an async
// `.text()`. A real browser's FileSystemDirectoryHandle satisfies this
// exactly; so does tests/fake-fs-access.js's in-memory tree.
// ---------------------------------------------------------------------

async function collectFilesFromDirectoryHandle(dirHandle, options = {}) {
  const maxBytes = options.maxFileBytes != null ? options.maxFileBytes : 2 * 1024 * 1024;
  const isBinaryByName = options.isBinaryByName || (() => false);

  const files = [];
  const skipped = [];

  async function walk(handle, path) {
    for await (const entry of handle.values()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      const entryPath = path ? `${path}/${entry.name}` : entry.name;
      if (entry.kind === "directory") {
        await walk(entry, entryPath);
      } else if (entry.kind === "file") {
        if (isBinaryByName(entryPath)) {
          skipped.push(entryPath);
          continue;
        }
        try {
          const file = await entry.getFile();
          if (file.size > maxBytes) {
            skipped.push(entryPath);
            continue;
          }
          const content = await file.text();
          files.push({ path: entryPath, content });
        } catch (e) {
          skipped.push(entryPath);
        }
      }
    }
  }

  await walk(dirHandle, "");
  return { files, skipped };
}

// ---------------------------------------------------------------------
// Ignore-list reconciliation - mirrors engine.py's hash_value()/
// check_ignore(): a finding is identified by (file, key, rule), never by
// its value directly. The stored "ignore" is a one-way SHA-256 hash of the
// value at the moment it was ignored, so the real value is never written
// to storage.js/IndexedDB, only its hash - if a later scan's candidate
// value hashes to something different, the finding reappears (flagged),
// rather than staying silently suppressed.
//
// SHA-256 here uses the Web Crypto API (`crypto.subtle`), available as a
// standard global in every modern browser AND in Node (used by the test
// script) - no hand-rolled crypto, no external dependency. Its only
// downside is that it's Promise-based, which is why this reconciliation
// happens as a separate pass AFTER scanFiles() rather than inline during
// redaction (keeping scanFiles() itself fully synchronous, so every
// existing call site and test is unaffected).
// ---------------------------------------------------------------------

async function hashValue(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Identifies a finding the same way engine.py's ignore_map keys do:
// (file, key, rule) - never the value itself. `key` may be null (e.g. a
// bare value-pattern match with no associated config key/variable name).
function ignoreKeyFor(file, key, rule) {
  return `${file}\u0000${key || ""}\u0000${rule}`;
}

// Replace the (occurrenceIndex)-th occurrence of `search` in `str` with
// `replacement` (0-indexed). Used to restore a suppressed finding's exact
// original text even when the same line contains more than one finding
// that happens to share identical replacement text (e.g. two MASKed values
// on one line) - each report entry's position in scan order determines
// which occurrence is "its" occurrence.
function replaceNthOccurrence(str, search, replacement, occurrenceIndex) {
  if (!search) return str;
  let idx = -1;
  for (let i = 0; i <= occurrenceIndex; i++) {
    idx = str.indexOf(search, idx + 1);
    if (idx === -1) return str;
  }
  return str.slice(0, idx) + replacement + str.slice(idx + search.length);
}

/**
 * Reconcile a completed scanFiles() result against a persisted ignore map.
 *
 * `ignoreMap`: a plain object, `{ [ignoreKeyFor(file,key,rule)]: storedHash }`
 * - exactly what storage.js's getIgnoreMap() returns. Not tied to
 * IndexedDB or any other storage mechanism here - this function only
 * consumes a plain object, so it's fully testable without a browser.
 *
 * For each report entry:
 *   - no matching ignore entry at all       -> kept as-is (unchanged)
 *   - matching entry, hash matches current  -> suppressed: removed from
 *                                              the report, original text
 *                                              restored in the output
 *   - matching entry, hash differs (or was
 *     never recorded)                       -> kept, flagged
 *                                              `previously_ignored_value_changed`,
 *                                              output stays redacted
 *
 * Returns a NEW { sanitizedFiles, reportEntries } - does not mutate the
 * input scanResult.
 */
async function applyIgnores(scanResult, ignoreMap) {
  const survivingEntries = [];
  const restorations = [];
  const occurrenceCounters = new Map();

  for (const entry of scanResult.reportEntries) {
    const occKey = `${entry.file}\u0000${entry.line}\u0000${entry.after}`;
    const occurrenceIndex = occurrenceCounters.get(occKey) || 0;
    occurrenceCounters.set(occKey, occurrenceIndex + 1);

    const ignoreKey = ignoreKeyFor(entry.file, entry.key, entry.rule);
    if (!Object.prototype.hasOwnProperty.call(ignoreMap, ignoreKey)) {
      survivingEntries.push(entry);
      continue;
    }

    const storedHash = ignoreMap[ignoreKey];
    const currentHash = await hashValue(entry.before);
    if (storedHash !== null && storedHash === currentHash) {
      // Still ignored - suppress, and (when there's non-empty replacement
      // text to look for - an emptied multiline-fragment placeholder has
      // nothing textual to restore) schedule restoring the original text.
      if (entry.after) {
        restorations.push({ file: entry.file, line: entry.line, after: entry.after, before: entry.before, occurrenceIndex });
      }
    } else {
      survivingEntries.push({ ...entry, previously_ignored_value_changed: true });
    }
  }

  if (restorations.length === 0) {
    return { sanitizedFiles: scanResult.sanitizedFiles, reportEntries: survivingEntries };
  }

  const restorationsByFile = new Map();
  for (const r of restorations) {
    if (!restorationsByFile.has(r.file)) restorationsByFile.set(r.file, []);
    restorationsByFile.get(r.file).push(r);
  }

  const patchedFiles = scanResult.sanitizedFiles.map((f) => {
    const fileRestorations = restorationsByFile.get(f.path);
    if (!fileRestorations || f.binary) return f;
    const lines = f.content.split("\n");
    for (const r of fileRestorations) {
      const idx = r.line - 1;
      if (lines[idx] !== undefined) {
        lines[idx] = replaceNthOccurrence(lines[idx], r.after, r.before, r.occurrenceIndex);
      }
    }
    return { path: f.path, content: lines.join("\n") };
  });

  return { sanitizedFiles: patchedFiles, reportEntries: survivingEntries };
}

if (typeof module !== "undefined") {
  module.exports = {
    scanFiles, MASK,
    scanMultilinePython, scanMultilinePlus, findKeyMatches,
    redactConfigLine, redactCodeLine, redactValuePatternsOnly,
    PlaceholderRegistry, categoryForKeyPattern, categoryForValuePattern,
    categoryForCodeKeyword, extractCodeKeyword, mostSpecificCategory,
    hashValue, ignoreKeyFor, applyIgnores, replaceNthOccurrence,
    computeEffectiveKeyPatterns, computeEffectivePlaceholderAllowlist,
    findKeyValue, quoteWrap, classifyFile,
    collectFilesFromDirectoryHandle,
    SKIP_DIRS,
    buildFileTree, indexFileTree, collectFilePaths,
    getNodeCheckState, setNodeChecked, filterFilesByCheckedPaths,
    reapplySavedSelection,
    getBaseRuleSnapshot,
  };
}
