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

// Short, generic words need boundary-aware matching to avoid false positives
// like "port" matching inside "support", or "auth" matching inside "author".
// Boundary = not adjacent to a letter/digit (underscore/dot/hyphen still count
// as valid separators, so db_port / db.port / db-port all still match).
function boundaryPattern(word) {
  return `(?<![A-Za-z0-9])${word}(?![A-Za-z0-9])`;
}

const KEY_PATTERNS = [
  "password", "passwd", "pwd", "secret", "token", "api[_-]?key", "apikey",
  "access[_-]?key", "private[_-]?key", "client[_-]?secret", boundaryPattern("auth"),
  "credential", "connection[_-]?string", "conn[_-]?str", "jdbc", "datasource\\.url",
  "db\\.url", "db\\.host", "db\\.password", "db\\.username", boundaryPattern("host"),
  "hostname", "ip[_-]?address", "endpoint", boundaryPattern("url"), boundaryPattern("uri"),
  boundaryPattern("ssn"), "encryption[_-]?key", "signing[_-]?key", "session[_-]?key",
  boundaryPattern("cert"), "keystore", "truststore", "username", boundaryPattern("port"),
].map((p) => new RegExp(p, "i"));

// Per-language: "suspicious variable/field name = string literal" in source code.
// Capture group 1 must be the string literal's inner content.
const CODE_PATTERNS = {
  java: [/(?:String|final\s+String)\s+\w*(?:password|secret|token|apikey|api_key|key|credential|auth)\w*\s*=\s*"([^"]*)"/i],
  python: [/\w*(?:password|secret|token|apikey|api_key|key|credential|auth)\w*\s*=\s*["']([^"']*)["']/i],
  javascript: [/(?:const|let|var)\s+\w*(?:password|secret|token|apikey|api_key|key|credential|auth)\w*\s*(?::\s*[\w<>|]+\s*)?=\s*[`"']([^`"']*)[`"']/i],
  go: [/\w*(?:password|secret|token|apikey|api_key|key|credential|auth)\w*\s*:?=\s*"([^"]*)"/i],
  csharp: [/(?:string|var)\s+\w*(?:password|secret|token|apikey|api_key|key|credential|auth)\w*\s*=\s*"([^"]*)"/i],
};

const VALUE_PATTERNS = [
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

const PLACEHOLDER_ALLOWLIST = new Set([
  "changeme", "change_me", "your_api_key_here", "your-api-key-here", "yourapikeyhere",
  "example", "dummy", "placeholder", "xxxxxxxx", "test123", "localhost", "127.0.0.1",
  "0.0.0.0", "none", "null", "n/a", "todo", "fixme", "insert_secret_here",
]);

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

  const keyMatched = KEY_PATTERNS.some((p) => p.test(key));

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
      // Note: multi-line concatenation detection (Python paren-style, Java/JS/C#
      // +-style) is intentionally not ported to this lightweight browser version -
      // single-line code patterns and value/entropy checks are covered, matching
      // the desktop app's single-line paths. Use the desktop app for full coverage
      // including multi-line concatenated secrets.
      const out = lines.map((l, i) => redactCodeLine(l, lang, i + 1, file.path, reportEntries));
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
  module.exports = { scanFiles, MASK };
}
