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
 */

const MASK = "***REDACTED***";

const CONFIG_EXTENSIONS = new Set([".properties", ".yml", ".yaml", ".json", ".xml", ".ini", ".conf", ".cfg"]);
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

const KEY_PATTERN_SOURCES = (SHARED_RULES && SHARED_RULES.key_patterns) || FALLBACK_KEY_PATTERN_SOURCES;

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

const PLACEHOLDER_ALLOWLIST = new Set(
  (SHARED_RULES && SHARED_RULES.placeholder_allowlist) || FALLBACK_PLACEHOLDER_ALLOWLIST
);

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

function findKeyValue(line) {
  const m = line.match(/^\s*([A-Za-z0-9_.\-\[\]]+)\s*[:=]\s*(.*)$/);
  if (!m) return [null, null];
  return [m[1], m[2]];
}

function redactConfigLine(line, lineNo, filename, reportEntries) {
  const [key, value] = findKeyValue(line);
  if (key === null) return redactValuePatternsOnly(line, lineNo, filename, reportEntries);
  if (value.trim() === "") return line;

  const keyMatched = KEY_PATTERN_SOURCES.some((src) => keyPatternMatchesStrict(src, key));

  if (keyMatched) {
    reportEntries.push({ file: filename, line: lineNo, key, rule: "key_name_match", before: value, after: MASK });
    return line.includes(value) ? line.replace(value, MASK) : `${key}=${MASK}`;
  }

  if (isPlaceholder(value)) return line;

  let valueMatchedName = null;
  for (const [name, pattern] of VALUE_PATTERNS) {
    if (pattern.test(value)) { valueMatchedName = name; break; }
  }
  const entropyFlag = looksHighEntropy(value);

  if (valueMatchedName || entropyFlag) {
    const reason = valueMatchedName || "high_entropy";
    reportEntries.push({ file: filename, line: lineNo, key, rule: reason, before: value, after: MASK });
    return line.includes(value) ? line.replace(value, MASK) : `${key}=${MASK}`;
  }

  return line;
}

function redactValuePatternsOnly(line, lineNo, filename, reportEntries) {
  let modified = line;
  for (const [name, pattern] of VALUE_PATTERNS) {
    const m = modified.match(pattern);
    if (m) {
      if (isPlaceholder(m[0])) continue;
      reportEntries.push({ file: filename, line: lineNo, key: null, rule: name, before: m[0], after: MASK });
      modified = modified.replace(pattern, MASK);
    }
  }
  return modified;
}

function redactCodeLine(line, lang, lineNo, filename, reportEntries) {
  let modified = line;
  const patterns = CODE_PATTERNS[lang] || [];

  for (const pattern of patterns) {
    const m = modified.match(pattern);
    if (m && m[1] !== undefined && m[1].trim() !== "") {
      const literalValue = m[1];
      const start = m.index + m[0].indexOf(m[1]);
      modified = modified.slice(0, start) + MASK + modified.slice(start + literalValue.length);
      reportEntries.push({ file: filename, line: lineNo, key: "code_literal", rule: "code_variable_pattern", before: literalValue, after: MASK });
    }
  }

  for (const [name, pattern] of VALUE_PATTERNS) {
    const m = modified.match(pattern);
    if (m && !modified.slice(m.index, m.index + m[0].length).includes(MASK)) {
      if (isPlaceholder(m[0])) continue;
      reportEntries.push({ file: filename, line: lineNo, key: null, rule: name, before: m[0], after: MASK });
      modified = modified.replace(pattern, MASK);
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

function findKeyMatches(name) {
  return KEY_PATTERN_SOURCES.some((src) => keyPatternMatchesCamel(src, name));
}

// Shared tail-end of both multiline scanners below: given the reconstructed
// value and where its fragments live, decide whether to redact and, if so,
// mask each fragment's quoted span in place and record one report entry per
// fragment - mirrors engine.py's shared key_hit/value_hit/entropy_hit gate.
function maybeRedactMultiline(varName, joined, fragIndices, fragments, lines, filename, reportEntries) {
  const keyHit = findKeyMatches(varName);
  let valueHit = null;
  for (const [name, pattern] of VALUE_PATTERNS) {
    if (pattern.test(joined)) { valueHit = name; break; }
  }
  const entropyHit = looksHighEntropy(joined);
  if (!(keyHit || valueHit || entropyHit)) return;
  if (!keyHit && isPlaceholder(joined)) return;

  const reason = keyHit ? "key_name_match" : (valueHit || "high_entropy");
  const rule = `multiline_concat_${reason}`;
  fragIndices.forEach((idx, k) => {
    const frag = fragments[k];
    lines[idx] = lines[idx].replace(/(["'])[^"']*\1/, (whole, q) => q + MASK + q);
    reportEntries.push({ file: filename, line: idx + 1, key: varName, rule, before: frag, after: MASK });
  });
}

/** Detect and redact `var = (\n "frag" \n "frag" \n)` across physical lines. */
function scanMultilinePython(lines, filename, reportEntries) {
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
        maybeRedactMultiline(varName, joined, fragIndices, fragments, lines, filename, reportEntries);
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
function scanMultilinePlus(lines, filename, reportEntries) {
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
        maybeRedactMultiline(varName, joined, fragIndices, fragments, lines, filename, reportEntries);
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
 * Returns { sanitizedFiles: [{path, content}], reportEntries: [...] }
 */
function scanFiles(files) {
  const reportEntries = [];
  const sanitizedFiles = [];

  for (const file of files) {
    const parts = file.path.split("/");
    if (parts.some((p) => SKIP_DIRS.has(p))) continue;

    const classification = classifyFile(file.path);
    const lines = file.content.split(/\r?\n/);

    if (classification === "config") {
      const out = lines.map((l, i) => redactConfigLine(l, i + 1, file.path, reportEntries));
      sanitizedFiles.push({ path: file.path, content: out.join("\n") });
    } else if (classification && classification.startsWith("code:")) {
      const lang = classification.split(":")[1];
      if (lang === "python") {
        scanMultilinePython(lines, file.path, reportEntries);
      }
      if (PLUS_CONCAT_LANGS.has(lang)) {
        scanMultilinePlus(lines, file.path, reportEntries);
      }
      const out = lines.map((l, i) => {
        if (l.includes(MASK)) return l; // already redacted by a multiline pass above - don't double-process
        return redactCodeLine(l, lang, i + 1, file.path, reportEntries);
      });
      sanitizedFiles.push({ path: file.path, content: out.join("\n") });
    } else if (classification === null && isLikelyTextFile(file.path)) {
      const out = lines.map((l, i) => redactValuePatternsOnly(l, i + 1, file.path, reportEntries));
      sanitizedFiles.push({ path: file.path, content: out.join("\n") });
    } else {
      sanitizedFiles.push({ path: file.path, content: file.content, binary: true });
    }
  }

  return { sanitizedFiles, reportEntries };
}

function isLikelyTextFile(path) {
  const binaryExts = [".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".exe", ".dll", ".so", ".woff", ".woff2", ".ttf"];
  const lower = path.toLowerCase();
  return !binaryExts.some((ext) => lower.endsWith(ext));
}

if (typeof module !== "undefined") {
  module.exports = {
    scanFiles, MASK,
    scanMultilinePython, scanMultilinePlus, findKeyMatches,
    redactConfigLine, redactCodeLine, redactValuePatternsOnly,
  };
}
