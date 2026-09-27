/**
 * Plain Node.js test script for scanner-engine.js - no framework, no
 * package.json, no dependencies (matches the site's own no-build-tool
 * constraint). Run with:
 *
 *     node tests/scanner-engine.test.js
 *
 * Exits non-zero if any assertion fails.
 */

const assert = require("assert");
const path = require("path");
const {
  scanFiles, MASK,
  scanMultilinePython, scanMultilinePlus, findKeyMatches,
  redactConfigLine, redactCodeLine, redactValuePatternsOnly,
  PlaceholderRegistry, categoryForKeyPattern, categoryForValuePattern,
  categoryForCodeKeyword, extractCodeKeyword, mostSpecificCategory,
  hashValue, ignoreKeyFor, applyIgnores, replaceNthOccurrence, reapplyRedaction,
  computeEffectiveKeyPatterns, computeEffectivePlaceholderAllowlist, getBaseRuleSnapshot,
  findKeyValue, quoteWrap, classifyFile,
  collectFilesFromDirectoryHandle,
  SKIP_DIRS, buildFileTree, indexFileTree, collectFilePaths,
  getNodeCheckState, setNodeChecked, filterFilesByCheckedPaths,
  reapplySavedSelection,
} = require(path.join(__dirname, "..", "scanner-engine.js"));
const { buildFakeDirectory } = require(path.join(__dirname, "fake-fs-access.js"));

let passed = 0;
let failed = 0;

// async so a test body can `await` (hashValue()/applyIgnores() are
// Promise-based - see scanner-engine.js's module comment for why). Every
// call site below is `await test(...)`, and the whole script body runs
// inside an async main() (see the bottom of this file) so tests execute
// strictly in order with correct pass/fail accounting either way.
async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ok  - ${name}`);
  } catch (e) {
    failed++;
    console.log(`FAIL  - ${name}`);
    console.log(`        ${e.message}`);
  }
}

async function main() {
// -----------------------------------------------------------------------
// PHASE 1 - multi-line concatenated secret detection
// -----------------------------------------------------------------------

console.log("Python parenthesized concatenation:");

await test("basic two-fragment concatenation is masked, both fragments gone", () => {
  const lines = [
    "API_SECRET = (",
    '    "fake"',
    '    "secret"',
    ")",
  ];
  const entries = [];
  scanMultilinePython(lines, "f.py", entries);
  const joined = lines.join("\n");
  assert.ok(!joined.includes("fakesecret"));
  assert.ok(!joined.includes("fake") && !joined.includes("secret"));
  assert.strictEqual(entries.length, 2, "one report entry per fragment line");
  assert.strictEqual(entries[0].rule, "multiline_concat_key_name_match");
});

await test("three-fragment concatenation - every fragment masked, line count unchanged", () => {
  const lines = [
    "db_password = (",
    '    "part1"',
    '    "part2"',
    '    "part3"',
    ")",
  ];
  const entries = [];
  scanMultilinePython(lines, "f.py", entries);
  assert.strictEqual(lines.length, 5, "line count must not change");
  assert.strictEqual(entries.length, 3);
  for (const l of ["part1", "part2", "part3"]) assert.ok(!lines.join("\n").includes(l));
});

await test("no closing paren - left untouched (malformed, not guessed at)", () => {
  const lines = [
    "API_SECRET = (",
    '    "fake"',
    '    "secret"',
    // no closing ')'
    "other_code_here()",
  ];
  const entries = [];
  scanMultilinePython(lines, "f.py", entries);
  assert.strictEqual(entries.length, 0);
  assert.ok(lines.join("\n").includes("fake") && lines.join("\n").includes("secret"));
});

await test("harmless variable name + non-sensitive value - not flagged", () => {
  const lines = [
    "message = (",
    '    "hello "',
    '    "world"',
    ")",
  ];
  const entries = [];
  scanMultilinePython(lines, "f.py", entries);
  assert.strictEqual(entries.length, 0);
  assert.ok(lines.join("\n").includes("hello"));
});

console.log("\nJava/JS/C# '+' concatenation (trailing-+ style):");

await test("Java trailing-+ style masks every fragment", () => {
  const lines = [
    'String authToken = "fake1234" +',
    '    "5678secret";',
  ];
  const entries = [];
  scanMultilinePlus(lines, "f.java", entries);
  const joined = lines.join("\n");
  assert.ok(!joined.includes("fake1234"));
  assert.ok(!joined.includes("5678secret"));
  assert.strictEqual(entries.length, 2);
});

await test("JavaScript trailing-+ style (const declaration) is masked", () => {
  const lines = [
    'const apiKey = "fakeJS1234" +',
    '    "moreSecretJS";',
  ];
  const entries = [];
  scanMultilinePlus(lines, "f.js", entries);
  const joined = lines.join("\n");
  assert.ok(!joined.includes("fakeJS1234"));
  assert.ok(!joined.includes("moreSecretJS"));
  assert.strictEqual(entries.length, 2);
});

await test("C# trailing-+ style (string declaration) is masked", () => {
  const lines = [
    'string clientSecret = "fakeCS1234" +',
    '    "moreSecretCS";',
  ];
  const entries = [];
  scanMultilinePlus(lines, "f.cs", entries);
  const joined = lines.join("\n");
  assert.ok(!joined.includes("fakeCS1234"));
  assert.ok(!joined.includes("moreSecretCS"));
  assert.strictEqual(entries.length, 2);
});

await test("three-fragment trailing-+ chain - all three fragments masked", () => {
  const lines = [
    'String authToken = "fake-plusfrag-one" +',
    '        "fake-plusfrag-two" +',
    '        "fake-plusfrag-three";',
  ];
  const entries = [];
  scanMultilinePlus(lines, "f.java", entries);
  assert.strictEqual(entries.length, 3);
  const joined = lines.join("\n");
  for (const frag of ["fake-plusfrag-one", "fake-plusfrag-two", "fake-plusfrag-three"]) {
    assert.ok(!joined.includes(frag));
  }
});

console.log("\nLeading-+ style:");

await test("Java leading-+ style masks every fragment", () => {
  const lines = [
    'String authToken = "fakeLead1234"',
    '    + "moreSecretLead";',
  ];
  const entries = [];
  scanMultilinePlus(lines, "f.java", entries);
  const joined = lines.join("\n");
  assert.ok(!joined.includes("fakeLead1234"));
  assert.ok(!joined.includes("moreSecretLead"));
  assert.strictEqual(entries.length, 2);
});

await test("leading-+ chain with three fragments, terminated by ';' on the last", () => {
  const lines = [
    'String secretValue = "fakeA"',
    '    + "fakeB"',
    '    + "fakeC";',
  ];
  const entries = [];
  scanMultilinePlus(lines, "f.java", entries);
  assert.strictEqual(entries.length, 3);
});

console.log("\nUnterminated / malformed chains - left untouched:");

await test("trailing-+ chain with no terminating ';' is left untouched entirely", () => {
  const lines = [
    'String authToken = "fake1234" +',
    '    "5678secret"', // no trailing + and no ';' - malformed
    "someOtherStatement();",
  ];
  const entries = [];
  scanMultilinePlus(lines, "f.java", entries);
  assert.strictEqual(entries.length, 0, "must not redact an unterminated chain");
  assert.ok(lines.join("\n").includes("fake1234"));
});

await test("single fragment only (no real concatenation) is not treated as multiline", () => {
  const lines = [
    'String authToken = "fake1234";', // already terminated on line 1, no continuation
    "int x = 5;",
  ];
  const entries = [];
  scanMultilinePlus(lines, "f.java", entries);
  assert.strictEqual(entries.length, 0);
});

console.log("\nGo parity (intentionally NOT covered, matching engine.py):");

await test("Go '+' concatenation is not detected (matches desktop's known limitation)", () => {
  const lines = [
    'authToken := "fakeGo1234" +',
    '    "moreSecretGo"',
  ];
  const entries = [];
  // Go is deliberately excluded from PLUS_CONCAT_LANGS - scanFiles() would
  // never call scanMultilinePlus for a .go file. Confirm directly too: even
  // if called, Go's ":=" operator doesn't match PLUS_ASSIGN_START's "=" only
  // syntax, so nothing should be flagged.
  scanMultilinePlus(lines, "f.go", entries);
  assert.strictEqual(entries.length, 0);
});

console.log("\nFull pipeline (scanFiles) - multiline integrates correctly with single-line pass:");

await test("scanFiles(): Python file with both a multiline secret and a single-line secret - both caught, no double-processing", () => {
  const files = [{
    path: "config.py",
    content: [
      "API_SECRET = (",
      '    "fake"',
      '    "secret"',
      ")",
      'db_password = "single-line-fake-pw"',
    ].join("\n"),
  }];
  const { sanitizedFiles, reportEntries } = scanFiles(files);
  assert.strictEqual(reportEntries.length, 3, "2 multiline fragments + 1 single-line finding");
  const out = sanitizedFiles[0].content;
  assert.ok(!out.includes("fake") || out.includes(MASK));
  assert.ok(!out.includes("secret") || out.includes(MASK));
  assert.ok(!out.includes("single-line-fake-pw"));
  // The multiline handler must have run before the single-line code-pattern
  // pass, and the already-redacted lines must be skipped by it (no MASK
  // duplicated onto an already-masked line).
  const maskCount = (out.match(/\*\*\*REDACTED\*\*\*/g) || []).length;
  assert.strictEqual(maskCount, 3);
});

await test("scanFiles(): Java file with a multiline secret - sanitized output never contains the real value", () => {
  const files = [{
    path: "Config.java",
    content: [
      "public class Config {",
      '    String authToken = "fakeToken123" +',
      '        "moreSecretPart";',
      "}",
    ].join("\n"),
  }];
  const { sanitizedFiles, reportEntries } = scanFiles(files);
  assert.strictEqual(reportEntries.length, 2);
  const out = sanitizedFiles[0].content;
  assert.ok(!out.includes("fakeToken123"));
  assert.ok(!out.includes("moreSecretPart"));
});

// -----------------------------------------------------------------------
// REGRESSION - existing single-line detection must be unaffected
// -----------------------------------------------------------------------

console.log("\nRegression - existing single-line behavior unchanged:");

await test("config key-name match still redacts (password=)", () => {
  const entries = [];
  const out = redactConfigLine("password=fakeSup3rSecret!", 1, "f.env", entries);
  assert.ok(out.includes(MASK));
  assert.strictEqual(entries.length, 1);
  assert.strictEqual(entries[0].rule, "key_name_match");
});

await test("config: ordinary non-secret value untouched", () => {
  const entries = [];
  const out = redactConfigLine("region=us-east-1", 1, "f.env", entries);
  assert.strictEqual(out, "region=us-east-1");
  assert.strictEqual(entries.length, 0);
});

await test("config: placeholder allow-list still suppresses a value-only match", () => {
  const entries = [];
  const out = redactConfigLine("some_value=localhost", 1, "f.env", entries);
  assert.strictEqual(entries.length, 0);
  assert.strictEqual(out, "some_value=localhost");
});

await test("value-pattern: AWS access key id still detected in free text", () => {
  const entries = [];
  const out = redactValuePatternsOnly("key = AKIAABCDEFGHIJKLMNOP", 1, "f.txt", entries);
  assert.ok(out.includes(MASK));
  assert.strictEqual(entries[0].rule, "aws_access_key_id");
});

await test("value-pattern: JWT still detected", () => {
  const entries = [];
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ";
  const out = redactValuePatternsOnly(`token: ${jwt}`, 1, "f.txt", entries);
  assert.ok(out.includes(MASK));
  assert.strictEqual(entries[0].rule, "jwt_token");
});

await test("code: single-line Java secret literal still detected (unrelated to multiline change)", () => {
  const entries = [];
  const out = redactCodeLine('String password = "fakeSingleLine123";', "java", 1, "f.java", entries);
  assert.ok(!out.includes("fakeSingleLine123"));
  assert.strictEqual(entries.length, 1);
});

await test("findKeyMatches(): camelCase-aware - 'authToken' matches, 'author' does not", () => {
  assert.strictEqual(findKeyMatches("authToken"), true);
  assert.strictEqual(findKeyMatches("author"), false);
});

await test("findKeyMatches(): 'dbPassword' matches via camelCase transition", () => {
  assert.strictEqual(findKeyMatches("dbPassword"), true);
});

await test("findKeyMatches(): a harmless variable name does not match", () => {
  assert.strictEqual(findKeyMatches("message"), false);
});

// -----------------------------------------------------------------------
// Data-driven rules sync (rules-data.js, generated from rules_default.yaml)
// -----------------------------------------------------------------------

console.log("\nData-driven rules sync (rules-data.js):");

await test("config: 'username' is no longer a key pattern (matches current rules_default.yaml)", () => {
  const entries = [];
  const out = redactConfigLine("username=admin", 1, "f.env", entries);
  assert.strictEqual(entries.length, 0, "username should not be flagged - it was removed from rules_default.yaml");
  assert.strictEqual(out, "username=admin");
});

await test("config: 'port' is no longer a key pattern (matches current rules_default.yaml)", () => {
  const entries = [];
  const out = redactConfigLine("port=5432", 1, "f.env", entries);
  assert.strictEqual(entries.length, 0, "port should not be flagged - it was removed from rules_default.yaml");
  assert.strictEqual(out, "port=5432");
});

await test("config: 'db_port' still fine (not a real secret either, and 'port' isn't a pattern anymore anyway)", () => {
  const entries = [];
  redactConfigLine("db_port=5432", 1, "f.env", entries);
  assert.strictEqual(entries.length, 0);
});

await test("bonus fix from switching to strict uniform boundary checking: 'secretary_name' no longer falsely matches bare 'secret'", () => {
  const entries = [];
  const out = redactConfigLine("secretary_name = John Smith", 1, "f.env", entries);
  assert.strictEqual(entries.length, 0, "'secret' must not match as a substring of 'secretary'");
  assert.strictEqual(out, "secretary_name = John Smith");
});

await test("uniform boundary checking still correctly matches genuine keys sharing a word boundary with 'secret'", () => {
  const entries = [];
  const out = redactConfigLine("client_secret=fakeSecretValue123", 1, "f.env", entries);
  assert.ok(out.includes(MASK));
  assert.strictEqual(entries.length, 1);
});

await test("bonus coverage gained from data-driven code_patterns: Python os.getenv(...) fallback default is now detected", () => {
  const entries = [];
  const out = redactCodeLine('DB_PASSWORD = os.getenv("DB_PASSWORD", "fake-PlainOldPassword1")', "python", 1, "f.py", entries);
  assert.ok(!out.includes("fake-PlainOldPassword1"), "the hardcoded fallback default should be masked");
  assert.ok(entries.length >= 1);
});

// -----------------------------------------------------------------------
// PHASE 2 - placeholder mode (typed, numbered placeholders)
// -----------------------------------------------------------------------

console.log("\nPlaceholderRegistry - determinism and distinctness (mirrors test_placeholders.py):");

await test("same value + same category gives the same placeholder", () => {
  const reg = new PlaceholderRegistry();
  const a = reg.getOrCreate("PASSWORD", "fakeSecret123");
  const b = reg.getOrCreate("PASSWORD", "fakeSecret123");
  assert.strictEqual(a, b);
});

await test("different values in the same category give different placeholders", () => {
  const reg = new PlaceholderRegistry();
  const a = reg.getOrCreate("API_KEY", "keyOne");
  const b = reg.getOrCreate("API_KEY", "keyTwo");
  assert.notStrictEqual(a, b);
});

await test("repeated value (3+ times) all correlate to the same token", () => {
  const reg = new PlaceholderRegistry();
  const first = reg.getOrCreate("GENERIC_SECRET", "PF001");
  const second = reg.getOrCreate("GENERIC_SECRET", "PF001");
  const third = reg.getOrCreate("GENERIC_SECRET", "PF001");
  assert.strictEqual(first, second);
  assert.strictEqual(second, third);
});

await test("same value under a different category gives a different placeholder (categories never share a counter)", () => {
  const reg = new PlaceholderRegistry();
  const a = reg.getOrCreate("PASSWORD", "sameRawValue");
  const b = reg.getOrCreate("API_KEY", "sameRawValue");
  assert.notStrictEqual(a, b);
});

await test("multiple categories get independent per-category counters", () => {
  const reg = new PlaceholderRegistry();
  assert.strictEqual(reg.getOrCreate("PASSWORD", "p1"), "<PASSWORD_1>");
  assert.strictEqual(reg.getOrCreate("API_KEY", "k1"), "<API_KEY_1>");
  assert.strictEqual(reg.getOrCreate("PASSWORD", "p2"), "<PASSWORD_2>");
  assert.strictEqual(reg.getOrCreate("API_KEY", "k2"), "<API_KEY_2>");
});

await test("placeholder text is built only from category + counter - never contains any part of the real value", () => {
  const reg = new PlaceholderRegistry();
  const secretValue = "SuperSecretDatabasePassword9000";
  const token = reg.getOrCreate("PASSWORD", secretValue);
  assert.ok(!token.includes(secretValue));
  // Not even a meaningful substring of it.
  assert.ok(!token.toLowerCase().includes("superdatabase"));
  assert.match(token, /^<PASSWORD_\d+>$/);
});

console.log("\nPlaceholder mode wired into detection functions:");

await test("config: key-name match produces a typed placeholder instead of MASK when a registry is given", () => {
  const reg = new PlaceholderRegistry();
  const entries = [];
  const out = redactConfigLine("password=fakeSup3rSecret!", 1, "f.env", entries, reg);
  assert.ok(!out.includes(MASK));
  assert.match(out, /password=<PASSWORD_1>/);
  assert.strictEqual(entries[0].after, "<PASSWORD_1>");
});

await test("config: same real value redacted under two different keys still correlates to one placeholder", () => {
  const reg = new PlaceholderRegistry();
  const e1 = [];
  const e2 = [];
  redactConfigLine("password=fakeShared123", 1, "f.env", e1, reg);
  redactConfigLine("db.password=fakeShared123", 2, "f.env", e2, reg);
  assert.strictEqual(e1[0].after, e2[0].after);
});

await test("config: quoted vs. unquoted occurrences of the same value still correlate (identity normalization)", () => {
  const reg = new PlaceholderRegistry();
  const e1 = [];
  const e2 = [];
  redactConfigLine('password="fakeQuoted123"', 1, "f.env", e1, reg);
  redactConfigLine("password=fakeQuoted123", 2, "f.env", e2, reg);
  assert.strictEqual(e1[0].after, e2[0].after);
});

await test("config: value-pattern match (no key hit) still gets a category-appropriate placeholder", () => {
  const reg = new PlaceholderRegistry();
  const entries = [];
  redactConfigLine("some_value=AKIAABCDEFGHIJKLMNOP", 1, "f.env", entries, reg);
  assert.match(entries[0].after, /^<API_KEY_\d+>$/);
});

await test("code: single-line literal gets a typed placeholder, category resolved from the variable name", () => {
  const reg = new PlaceholderRegistry();
  const entries = [];
  const out = redactCodeLine('String apiKey = "fakeApiKeyValue123";', "java", 1, "f.java", entries, reg);
  assert.ok(!out.includes("fakeApiKeyValue123"));
  assert.match(entries[0].after, /^<API_KEY_\d+>$/);
});

await test("multiline (Python paren-style): whole value gets ONE placeholder on the first fragment, rest emptied", () => {
  const reg = new PlaceholderRegistry();
  const lines = [
    "API_SECRET = (",
    '    "fake-frag-one"',
    '    "fake-frag-two"',
    ")",
  ];
  const entries = [];
  scanMultilinePython(lines, "f.py", entries, reg);
  assert.strictEqual(lines.length, 4, "line count unchanged");
  assert.match(entries[0].after, /^</);
  assert.strictEqual(entries[1].after, "");
  const joined = lines.join("\n");
  assert.ok(!joined.includes("fake-frag-one"));
  assert.ok(!joined.includes("fake-frag-two"));
});

await test("multiline (Java plus-style, 3 fragments): one placeholder on the first fragment, both later ones emptied", () => {
  const reg = new PlaceholderRegistry();
  const lines = [
    'String authToken = "fake-plusfrag-one" +',
    '        "fake-plusfrag-two" +',
    '        "fake-plusfrag-three";',
  ];
  const entries = [];
  scanMultilinePlus(lines, "f.java", entries, reg);
  assert.match(entries[0].after, /^<ACCESS_TOKEN_\d+>$/);
  assert.strictEqual(entries[1].after, "");
  assert.strictEqual(entries[2].after, "");
  const joined = lines.join("\n");
  for (const frag of ["fake-plusfrag-one", "fake-plusfrag-two", "fake-plusfrag-three"]) {
    assert.ok(!joined.includes(frag));
  }
  // Still syntactically a 3-term concatenation, not collapsed to one line.
  assert.strictEqual((joined.match(/\+/g) || []).length, 2);
});

await test("multiline value correlates with a single-line occurrence of the same reconstructed value elsewhere", () => {
  const reg = new PlaceholderRegistry();
  const multilineLines = [
    'String authToken = "fakeAB" +',
    '        "CD90";',
  ];
  const entries = [];
  scanMultilinePlus(multilineLines, "f.java", entries, reg);
  const multilinePlaceholder = entries[0].after;

  const singleEntries = [];
  redactCodeLine('String backupAuthToken = "fakeABCD90";', "java", 2, "f.java", singleEntries, reg);
  assert.strictEqual(singleEntries[0].after, multilinePlaceholder);
});

console.log("\nFull pipeline (scanFiles) with placeholderMode option:");

await test("scanFiles({placeholderMode:false}) (default) - unchanged MASK behavior", () => {
  const files = [{ path: "app.properties", content: "password=fakeDefault123" }];
  const { sanitizedFiles } = scanFiles(files);
  assert.ok(sanitizedFiles[0].content.includes(MASK));
});

await test("scanFiles({placeholderMode:true}) - typed placeholders throughout, no MASK anywhere", () => {
  const files = [{
    path: "app.properties",
    content: [
      "password=fakeAppPass123",
      "api_key=fakeAppKey456",
    ].join("\n"),
  }];
  const { sanitizedFiles, reportEntries } = scanFiles(files, { placeholderMode: true });
  const out = sanitizedFiles[0].content;
  assert.ok(!out.includes(MASK));
  assert.ok(out.includes("<PASSWORD_1>"));
  assert.ok(out.includes("<API_KEY_1>"));
  assert.strictEqual(reportEntries.length, 2);
});

await test("scanFiles({placeholderMode:true}) - determinism: repeated scans of the same input produce identical output", () => {
  const files = [{
    path: "app.properties",
    content: ["api_key=fakeDetKey1", "another_key=fakeDetKey2", "third=fakeDetKey1"].join("\n"),
  }];
  const run1 = scanFiles(files, { placeholderMode: true });
  const run2 = scanFiles(files, { placeholderMode: true });
  assert.strictEqual(run1.sanitizedFiles[0].content, run2.sanitizedFiles[0].content);
});

await test("scanFiles({placeholderMode:true}) - distinctness across an entire multi-file scan: two different secrets never share a token", () => {
  const files = [
    { path: "a.properties", content: "password=fakeUniqueValueOne" },
    { path: "b.properties", content: "password=fakeUniqueValueTwo" },
  ];
  const { reportEntries } = scanFiles(files, { placeholderMode: true });
  assert.strictEqual(reportEntries.length, 2);
  assert.notStrictEqual(reportEntries[0].after, reportEntries[1].after);
});

await test("scanFiles({placeholderMode:true}) - the same secret repeated across two different files still correlates", () => {
  const files = [
    { path: "a.properties", content: "password=fakeSharedAcrossFiles" },
    { path: "b.properties", content: "backup_password=fakeSharedAcrossFiles" },
  ];
  const { reportEntries } = scanFiles(files, { placeholderMode: true });
  assert.strictEqual(reportEntries[0].after, reportEntries[1].after);
});

await test("scanFiles({placeholderMode:true}) - no original secret value remains anywhere in the sanitized output", () => {
  const files = [{
    path: "secrets.py",
    content: [
      'API_SECRET = (',
      '    "fakeMultilinePartA"',
      '    "fakeMultilinePartB"',
      ')',
      'password = "fakeSingleLineSecret"',
    ].join("\n"),
  }];
  const { sanitizedFiles } = scanFiles(files, { placeholderMode: true });
  const out = sanitizedFiles[0].content;
  for (const secret of ["fakeMultilinePartA", "fakeMultilinePartB", "fakeSingleLineSecret"]) {
    assert.ok(!out.includes(secret));
  }
});

await test("category helpers resolve as expected (spot checks against engine.py's mapping tables)", () => {
  assert.strictEqual(categoryForKeyPattern("password"), "PASSWORD");
  assert.strictEqual(categoryForKeyPattern("api[_-]?key"), "API_KEY");
  assert.strictEqual(categoryForKeyPattern("some_unmapped_future_pattern"), "GENERIC_SECRET");
  assert.strictEqual(categoryForValuePattern("aws_access_key_id"), "API_KEY");
  assert.strictEqual(categoryForValuePattern("high_entropy"), "GENERIC_SECRET");
  assert.strictEqual(categoryForCodeKeyword("apikey"), "API_KEY");
  assert.strictEqual(categoryForCodeKeyword("key"), "GENERIC_SECRET");
  assert.strictEqual(extractCodeKeyword("String apiKeyForService"), "apikey");
  assert.strictEqual(mostSpecificCategory(["GENERIC_SECRET", "API_KEY"]), "API_KEY");
  assert.strictEqual(mostSpecificCategory(["GENERIC_SECRET", "GENERIC_SECRET"]), "GENERIC_SECRET");
});

// -----------------------------------------------------------------------
// PHASE 3 - ignore-list hash verification (applyIgnores/hashValue)
// -----------------------------------------------------------------------

console.log("\nhashValue() - standard SHA-256 (Web Crypto), known test vectors:");

await test("SHA-256 of the empty string matches the well-known vector", async () => {
  assert.strictEqual(await hashValue(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
});

await test("SHA-256 of 'abc' matches the well-known vector", async () => {
  assert.strictEqual(await hashValue("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});

await test("hashValue is deterministic and distinguishes different inputs", async () => {
  const h1 = await hashValue("fakeSecretABC");
  const h2 = await hashValue("fakeSecretABC");
  const h3 = await hashValue("fakeSecretXYZ");
  assert.strictEqual(h1, h2);
  assert.notStrictEqual(h1, h3);
});

console.log("\napplyIgnores() - suppression, change-detection, and restoration:");

await test("no matching ignore entry - report entry and output untouched", async () => {
  const scanResult = { sanitizedFiles: [{ path: "f.env", content: `password=${MASK}` }], reportEntries: [{ file: "f.env", line: 1, key: "password", rule: "key_name_match", before: "fakeVal", after: MASK }] };
  const result = await applyIgnores(scanResult, {});
  assert.strictEqual(result.reportEntries.length, 1);
  assert.strictEqual(result.sanitizedFiles[0].content, `password=${MASK}`);
});

await test("matching ignore + unchanged value - suppressed from report AND original text restored in output", async () => {
  const before = "fakeIgnoredSecret";
  const hash = await hashValue(before);
  const ignoreMap = { [ignoreKeyFor("f.env", "password", "key_name_match")]: hash };
  const scanResult = {
    sanitizedFiles: [{ path: "f.env", content: `password=${MASK}` }],
    reportEntries: [{ file: "f.env", line: 1, key: "password", rule: "key_name_match", before, after: MASK }],
  };
  const result = await applyIgnores(scanResult, ignoreMap);
  assert.strictEqual(result.reportEntries.length, 0, "suppressed from the report entirely");
  assert.strictEqual(result.sanitizedFiles[0].content, `password=${before}`, "original value restored in the sanitized output");
});

await test("matching ignore + CHANGED value - reappears, flagged, output stays redacted (not silently suppressed)", async () => {
  const oldValue = "fakeOldSecret";
  const staleHash = await hashValue(oldValue); // hash recorded against the OLD value
  const newValue = "fakeRotatedSecret"; // the value has since changed
  const ignoreMap = { [ignoreKeyFor("f.env", "password", "key_name_match")]: staleHash };
  const scanResult = {
    sanitizedFiles: [{ path: "f.env", content: `password=${MASK}` }],
    reportEntries: [{ file: "f.env", line: 1, key: "password", rule: "key_name_match", before: newValue, after: MASK }],
  };
  const result = await applyIgnores(scanResult, ignoreMap);
  assert.strictEqual(result.reportEntries.length, 1, "must NOT be silently suppressed");
  assert.strictEqual(result.reportEntries[0].previously_ignored_value_changed, true);
  assert.strictEqual(result.sanitizedFiles[0].content, `password=${MASK}`, "stays redacted, not reverted to the new real value");
});

await test("ignore entry with hash null (recorded with no hash) always reflags rather than suppressing", async () => {
  const ignoreMap = { [ignoreKeyFor("f.env", "password", "key_name_match")]: null };
  const scanResult = {
    sanitizedFiles: [{ path: "f.env", content: `password=${MASK}` }],
    reportEntries: [{ file: "f.env", line: 1, key: "password", rule: "key_name_match", before: "fakeAnyValue", after: MASK }],
  };
  const result = await applyIgnores(scanResult, ignoreMap);
  assert.strictEqual(result.reportEntries.length, 1);
  assert.strictEqual(result.reportEntries[0].previously_ignored_value_changed, true);
});

await test("two findings on the same line sharing identical replacement text - ignoring one restores only that occurrence", async () => {
  const before1 = "fakeLineSecretOne";
  const before2 = "fakeLineSecretTwo";
  const hash1 = await hashValue(before1);
  // Only the FIRST finding on the line is ignored.
  const ignoreMap = { [ignoreKeyFor("f.env", "password", "key_name_match")]: hash1 };
  const scanResult = {
    sanitizedFiles: [{ path: "f.env", content: `password=${MASK} password2=${MASK}` }],
    reportEntries: [
      { file: "f.env", line: 1, key: "password", rule: "key_name_match", before: before1, after: MASK },
      { file: "f.env", line: 1, key: "password2", rule: "key_name_match", before: before2, after: MASK },
    ],
  };
  const result = await applyIgnores(scanResult, ignoreMap);
  assert.strictEqual(result.reportEntries.length, 1, "only the second (not ignored) finding remains reported");
  assert.strictEqual(result.reportEntries[0].before, before2);
  assert.strictEqual(result.sanitizedFiles[0].content, `password=${before1} password2=${MASK}`, "first occurrence restored, second stays masked");
});

await test("end-to-end scenario matching the exact desktop-parity spec: ignore -> rescan suppressed -> value changes -> rescan reflagged", async () => {
  // 1. Original scan finds a secret.
  const files1 = [{ path: "app.properties", content: "api_key=fakeOriginalKey123" }];
  const scan1 = scanFiles(files1);
  assert.strictEqual(scan1.reportEntries.length, 1);
  const finding = scan1.reportEntries[0];

  // 2. User reviews it and clicks "ignore" - the app hashes the CURRENT value and stores it.
  const storedHash = await hashValue(finding.before);
  const ignoreMap = { [ignoreKeyFor(finding.file, finding.key, finding.rule)]: storedHash };

  // 3. Re-scan with the SAME (unchanged) source - ignore should suppress it.
  const scan2 = scanFiles(files1);
  const reconciled2 = await applyIgnores(scan2, ignoreMap);
  assert.strictEqual(reconciled2.reportEntries.length, 0, "unchanged value: suppressed");
  assert.ok(reconciled2.sanitizedFiles[0].content.includes("fakeOriginalKey123"), "restored to original in the output");

  // 4. The underlying value changes (e.g. key rotated) - re-scan with the SAME STALE ignoreMap.
  const files2 = [{ path: "app.properties", content: "api_key=fakeRotatedKey456" }];
  const scan3 = scanFiles(files2);
  const reconciled3 = await applyIgnores(scan3, ignoreMap);
  assert.strictEqual(reconciled3.reportEntries.length, 1, "changed value: reappears, not silently suppressed");
  assert.strictEqual(reconciled3.reportEntries[0].previously_ignored_value_changed, true);
  assert.ok(!reconciled3.sanitizedFiles[0].content.includes("fakeRotatedKey456"), "new value stays redacted");
});

console.log("\nreapplyRedaction() - reversing an ignore (revertible ignores, checkpoint 1):");

await test("applyIgnores() returns a restoredEntries list carrying the occurrenceIndex used for each restoration", async () => {
  const before = "fakeRestoreMe";
  const hash = await hashValue(before);
  const ignoreMap = { [ignoreKeyFor("f.env", "password", "key_name_match")]: hash };
  const scanResult = {
    sanitizedFiles: [{ path: "f.env", content: `password=${MASK}` }],
    reportEntries: [{ file: "f.env", line: 1, key: "password", rule: "key_name_match", before, after: MASK }],
  };
  const result = await applyIgnores(scanResult, ignoreMap);
  assert.strictEqual(result.restoredEntries.length, 1);
  assert.strictEqual(result.restoredEntries[0].before, before);
  assert.strictEqual(result.restoredEntries[0].occurrenceIndex, 0);
});

await test("reapplyRedaction() reverses a MASK restoration: masked -> ignored/unmasked -> restored/masked again", () => {
  const before = "fakeRoundTripSecret";
  const sanitizedAfterIgnore = [{ path: "f.env", content: `password=${before}` }];
  const entry = { file: "f.env", line: 1, key: "password", rule: "key_name_match", before, after: MASK, occurrenceIndex: 0 };
  const reMasked = reapplyRedaction(sanitizedAfterIgnore, entry);
  assert.strictEqual(reMasked[0].content, `password=${MASK}`);
  // Original array untouched (pure function).
  assert.strictEqual(sanitizedAfterIgnore[0].content, `password=${before}`);
});

await test("reapplyRedaction() restores the correct PLACEHOLDER token, not just MASK, when the original scan ran in placeholder mode", () => {
  const files = [{ path: "app.properties", content: "api_key=fakePlaceholderRoundTrip123" }];
  const scan = scanFiles(files, { placeholderMode: true });
  const entry = scan.reportEntries[0];
  assert.notStrictEqual(entry.after, MASK, "sanity check: placeholder mode really did produce a token, not ***REDACTED***");

  // Simulate: ignore this entry (restores the real value)...
  const unmasked = scan.sanitizedFiles.map((f) => ({ ...f, content: f.content.replace(entry.after, entry.before) }));
  // ...then restore the redaction (should bring back the SAME placeholder token).
  const reMasked = reapplyRedaction(unmasked, { ...entry, occurrenceIndex: 0 });
  assert.ok(reMasked[0].content.includes(entry.after), "the original placeholder token, not a generic mask, is restored");
  assert.ok(!reMasked[0].content.includes(entry.before), "the real value is no longer present");
});

await test("reapplyRedaction() is a no-op (returns input unchanged) when entry.after is empty - mirrors applyIgnores()'s own skip", () => {
  const sanitized = [{ path: "f.env", content: "unrelated content" }];
  const entry = { file: "f.env", line: 1, before: "x", after: "", occurrenceIndex: 0 };
  const result = reapplyRedaction(sanitized, entry);
  assert.strictEqual(result, sanitized);
});

await test("reapplyRedaction() only touches the matching file, leaving others untouched", () => {
  const sanitized = [
    { path: "a.env", content: "password=realValueA" },
    { path: "b.env", content: "password=realValueA" }, // same real value, different file
  ];
  const entry = { file: "a.env", line: 1, before: "realValueA", after: MASK, occurrenceIndex: 0 };
  const result = reapplyRedaction(sanitized, entry);
  assert.strictEqual(result.find((f) => f.path === "a.env").content, `password=${MASK}`);
  assert.strictEqual(result.find((f) => f.path === "b.env").content, "password=realValueA", "other files are untouched");
});

await test("end-to-end: ignore then restore round-trips back to the exact original masked output", async () => {
  const files = [{ path: "app.properties", content: "api_key=fakeEndToEndRoundTrip789" }];
  const scan = scanFiles(files);
  const originalMaskedContent = scan.sanitizedFiles[0].content;
  const entry = scan.reportEntries[0];

  // Ignore it.
  const hash = await hashValue(entry.before);
  const ignoreMap = { [ignoreKeyFor(entry.file, entry.key, entry.rule)]: hash };
  const afterIgnore = await applyIgnores(scan, ignoreMap);
  assert.strictEqual(afterIgnore.reportEntries.length, 0);
  assert.strictEqual(afterIgnore.restoredEntries.length, 1);

  // Restore it using the occurrenceIndex applyIgnores() handed back.
  const restoredEntry = afterIgnore.restoredEntries[0];
  const afterRestore = reapplyRedaction(afterIgnore.sanitizedFiles, restoredEntry);
  assert.strictEqual(afterRestore[0].content, originalMaskedContent, "back to exactly the original masked output");
});

// -----------------------------------------------------------------------
// PHASE 4 - visual rule editor: per-session overrides layered on the base
// -----------------------------------------------------------------------

console.log("\ncomputeEffectiveKeyPatterns() / computeEffectivePlaceholderAllowlist() - pure merge logic:");

await test("no overrides - effective list equals the base list (same content, different array instance)", () => {
  const base = getBaseRuleSnapshot();
  const effective = computeEffectiveKeyPatterns(null);
  assert.deepStrictEqual(effective, base.keyPatternSources);
});

await test("added key pattern appears in the effective list, base list is untouched", () => {
  const before = getBaseRuleSnapshot();
  const effective = computeEffectiveKeyPatterns({ keyPatternsAdded: ["totallycustomsecret"], keyPatternsRemoved: [] });
  assert.ok(effective.includes("totallycustomsecret"));
  const after = getBaseRuleSnapshot();
  assert.deepStrictEqual(before, after, "base snapshot must be byte-identical before and after");
});

await test("removed key pattern is absent from the effective list, base list still has it", () => {
  const effective = computeEffectiveKeyPatterns({ keyPatternsAdded: [], keyPatternsRemoved: ["password"] });
  assert.ok(!effective.includes("password"));
  const base = getBaseRuleSnapshot();
  assert.ok(base.keyPatternSources.includes("password"), "base is untouched - still has 'password'");
});

await test("placeholder-allowlist add/remove, case-insensitive", () => {
  const effective = computeEffectivePlaceholderAllowlist({
    placeholderAllowlistAdded: ["MyTeamsSharedFakeToken"],
    placeholderAllowlistRemoved: ["DUMMY"], // base has "dummy" - must match case-insensitively
  });
  assert.ok(effective.includes("myteamssharedfaketoken"));
  assert.ok(!effective.map((v) => v.toLowerCase()).includes("dummy"));
});

console.log("\nscanFiles({ ruleOverrides }) - overrides actually affect detection, base rules never modified:");

await test("adding a custom key pattern makes scanFiles() detect a key it wouldn't otherwise", () => {
  const files = [{ path: "app.properties", content: "totallycustomsecret=fakeCustomValue123" }];
  const withoutOverride = scanFiles(files);
  assert.strictEqual(withoutOverride.reportEntries.length, 0, "not detected without the override");

  const withOverride = scanFiles(files, { ruleOverrides: { keyPatternsAdded: ["totallycustomsecret"], keyPatternsRemoved: [] } });
  assert.strictEqual(withOverride.reportEntries.length, 1, "detected once the user adds this pattern locally");
  assert.ok(!withOverride.sanitizedFiles[0].content.includes("fakeCustomValue123"));
});

await test("removing 'password' via override stops THIS scan from flagging it, without touching the base", () => {
  const files = [{ path: "app.properties", content: "password=fakeStillSecret123" }];
  const withOverride = scanFiles(files, { ruleOverrides: { keyPatternsAdded: [], keyPatternsRemoved: ["password"] } });
  assert.strictEqual(withOverride.reportEntries.length, 0, "suppressed for this scan by the local override");

  // A later scan with NO override must behave exactly as before - the
  // override must not have leaked into the shared base.
  const withoutOverride = scanFiles(files);
  assert.strictEqual(withoutOverride.reportEntries.length, 1, "base behavior fully restored for a scan with no override");
});

await test("base rule snapshot is byte-identical before and after a scan that uses overrides", () => {
  const before = getBaseRuleSnapshot();
  scanFiles(
    [{ path: "app.properties", content: "password=fakeVal\ncustomthing=fakeVal2" }],
    { ruleOverrides: { keyPatternsAdded: ["customthing"], keyPatternsRemoved: ["password"] } }
  );
  const after = getBaseRuleSnapshot();
  assert.deepStrictEqual(before, after);
});

await test("adding a placeholder-allowlist entry suppresses a value/entropy-only finding for this scan only", () => {
  const files = [{ path: "app.properties", content: "some_value=MyTeamsSharedFakeToken1234567890AB" }];
  const withoutOverride = scanFiles(files);
  assert.strictEqual(withoutOverride.reportEntries.length, 1, "flagged as high-entropy without the override");

  const withOverride = scanFiles(files, {
    ruleOverrides: { placeholderAllowlistAdded: ["myteamssharedfaketoken1234567890ab"], placeholderAllowlistRemoved: [] },
  });
  assert.strictEqual(withOverride.reportEntries.length, 0, "suppressed once locally allow-listed");

  const afterOverride = scanFiles(files);
  assert.strictEqual(afterOverride.reportEntries.length, 1, "base behavior restored for a scan with no override");
});

await test("overrides reach multiline detection too (findKeyMatches consults the same effective KEY_PATTERN_SOURCES scanFiles() swaps in)", () => {
  const lines = ["totallycustomsecret = (", '    "fake"', '    "secret"', ")"];

  const withoutOverrideEntries = [];
  scanMultilinePython(lines.slice(), "f.py", withoutOverrideEntries);
  assert.strictEqual(withoutOverrideEntries.length, 0, "not matched without the override");

  const files = [{ path: "f.py", content: lines.join("\n") }];
  const withOverride = scanFiles(files, { ruleOverrides: { keyPatternsAdded: ["totallycustomsecret"], keyPatternsRemoved: [] } });
  assert.strictEqual(withOverride.reportEntries.length, 2, "multiline concatenation now matched via the added key pattern");
});

await test("does not break Phase 1 (multiline) / Phase 2 (placeholder mode) when combined with ruleOverrides", () => {
  const files = [{
    path: "Config.java",
    content: [
      'String totallycustomsecret = "fakePart1" +',
      '    "fakePart2";',
    ].join("\n"),
  }];
  const result = scanFiles(files, {
    placeholderMode: true,
    ruleOverrides: { keyPatternsAdded: ["totallycustomsecret"], keyPatternsRemoved: [] },
  });
  assert.strictEqual(result.reportEntries.length, 2);
  assert.match(result.reportEntries[0].after, /^</, "placeholder mode still applies alongside rule overrides");
  assert.ok(!result.sanitizedFiles[0].content.includes("fakePart1"));
  assert.ok(!result.sanitizedFiles[0].content.includes("fakePart2"));
});

// -----------------------------------------------------------------------
// JSON / XML / .config detection - ported from engine.py's
// _KV_XML_ATTR_PAIR/_KV_XML_ELEMENT/_KV_JSON_KEY, using the desktop's own
// pinned regression fixtures (tests/test_regressions.py in the app repo)
// as the reference input for each, adapted only by dropping the trailing
// "\n" the Python fixtures include - lines reach redactConfigLine() in
// this codebase without a trailing newline (scanFiles() splits on \r?\n
// first), consistent with every other existing test in this file.
// -----------------------------------------------------------------------

console.log("\nJSON quoted-key detection (desktop-pinned fixtures):");

await test("[desktop: test_f1_json_quoted_key_is_detected] quoted JSON key/value is detected and redacted, quotes preserved", () => {
  const entries = [];
  const out = redactConfigLine('  "password": "fake-supersecret123",', 1, "f.json", entries);
  assert.ok(!out.includes("fake-supersecret123"));
  assert.strictEqual(entries.length, 1);
  assert.strictEqual(entries[0].key, "password");
  assert.strictEqual(entries[0].rule, "key_name_match");
  assert.strictEqual(out.trim(), `"password": "${MASK}",`);
});

await test("[desktop: test_f1_json_short_low_entropy_secret_is_still_caught_via_key_name] a short, low-entropy value is still caught via the key name", () => {
  const entries = [];
  const out = redactConfigLine('  "db_password" : "hunter2",', 1, "f.json", entries);
  assert.ok(!out.includes("hunter2"));
  assert.strictEqual(entries[0].rule, "key_name_match");
});

await test("[desktop: test_f1_json_object_opener_is_not_treated_as_a_scalar_value] a nested-object opener is left completely untouched", () => {
  const entries = [];
  const line = '  "auth": {';
  const out = redactConfigLine(line, 1, "f.json", entries);
  assert.strictEqual(out, line);
  assert.strictEqual(entries.length, 0);
});

await test("own fixture: JSON array opener is also left untouched (same guard as the object-opener case)", () => {
  const entries = [];
  const line = '  "tags": [';
  const out = redactConfigLine(line, 1, "f.json", entries);
  assert.strictEqual(out, line);
  assert.strictEqual(entries.length, 0);
});

await test("own fixture: JSON value-pattern-only match (no key hit) is still detected through the new JSON shape", () => {
  const entries = [];
  const out = redactConfigLine('  "note": "AKIAABCDEFGHIJKLMNOP",', 1, "f.json", entries);
  assert.ok(!out.includes("AKIAABCDEFGHIJKLMNOP"));
  assert.strictEqual(entries[0].rule, "aws_access_key_id");
});

await test("own fixture: placeholder mode on a JSON line still preserves the surrounding quotes", () => {
  const reg = new PlaceholderRegistry();
  const entries = [];
  const out = redactConfigLine('  "api_key": "fakeJsonKey123",', 1, "f.json", entries, reg);
  assert.match(out.trim(), /^"api_key": "<API_KEY_\d+>",$/);
});

console.log("\nXML element-text detection (desktop-pinned fixtures):");

await test("[desktop: test_f1_xml_element_is_detected] <password>value</password> is detected and redacted", () => {
  const entries = [];
  const out = redactConfigLine("<password>fake-password</password>", 1, "f.xml", entries);
  assert.ok(!out.includes("fake-password"));
  assert.strictEqual(out.trim(), `<password>${MASK}</password>`);
});

await test("own fixture: XML element with a non-matching tag name but a suspicious VALUE is still caught via value-pattern", () => {
  const entries = [];
  const out = redactConfigLine("<note>AKIAABCDEFGHIJKLMNOP</note>", 1, "f.xml", entries);
  assert.ok(!out.includes("AKIAABCDEFGHIJKLMNOP"));
  assert.strictEqual(entries[0].rule, "aws_access_key_id");
});

await test("own fixture: XML element with harmless content is left untouched", () => {
  const entries = [];
  const line = "<environment>production</environment>";
  const out = redactConfigLine(line, 1, "f.xml", entries);
  assert.strictEqual(out, line);
  assert.strictEqual(entries.length, 0);
});

console.log("\nXML/.config attribute-pair detection (desktop-pinned fixtures):");

await test("[desktop: test_f1_dotnet_config_attribute_pair_is_detected] <add key=\"password\" value=\"...\"/> is detected, key attribute untouched", () => {
  const entries = [];
  const line = '    <add key="password" value="fake-password"/>';
  const out = redactConfigLine(line, 1, "Web.config", entries);
  assert.ok(!out.includes("fake-password"));
  assert.ok(out.includes('key="password"'), "the key attribute itself is untouched");
  assert.ok(out.includes(`value="${MASK}"`));
});

await test("[desktop: test_f1_dotnet_config_connection_string_attribute] a ConnectionString-style attribute pair is detected", () => {
  const entries = [];
  const line = '<add key="ConnectionString" value="Server=fake-host;Password=fake-Sup3rSecret!"/>';
  const out = redactConfigLine(line, 1, "Web.config", entries);
  assert.ok(!out.includes("fake-Sup3rSecret!"));
  assert.strictEqual(entries[0].key, "ConnectionString");
});

await test("[desktop: test_f1_dotconfig_extension_is_classified_as_config] .config files are classified as config", () => {
  assert.strictEqual(classifyFile("Web.config"), "config");
  assert.strictEqual(classifyFile("App.config"), "config");
});

await test("own fixture: full scanFiles() pipeline correctly redacts a .config file end-to-end", () => {
  const files = [{ path: "Web.config", content: '<add key="password" value="fakeEndToEnd123"/>' }];
  const { sanitizedFiles, reportEntries } = scanFiles(files);
  assert.strictEqual(reportEntries.length, 1);
  assert.ok(!sanitizedFiles[0].content.includes("fakeEndToEnd123"));
});

await test("own fixture: single-quoted .config attribute values are also matched (not just double-quoted)", () => {
  const entries = [];
  const line = "<add key='password' value='fake-single-quoted'/>";
  const out = redactConfigLine(line, 1, "Web.config", entries);
  assert.ok(!out.includes("fake-single-quoted"));
  assert.ok(out.includes(`value='${MASK}'`));
});

console.log("\nQuote-preservation fix (bonus correctness improvement from this refactor):");

await test("own fixture: a double-quoted properties-style value now preserves its quotes (previously stripped entirely)", () => {
  const entries = [];
  const out = redactConfigLine('password = "fakeQuotedProps123"', 1, "f.properties", entries);
  assert.strictEqual(out, `password = "${MASK}"`);
});

await test("own fixture: YAML block-scalar header is left alone even when the key itself matches a key pattern", () => {
  // "encryption_key" matches the "encryption[_-]?key" key pattern, but the
  // VALUE here is a bare block-scalar header, not a redactable leaf - the
  // real content is the indented lines that would follow, never seen as
  // this key's value at all (same guard as the JSON {/[ opener case).
  const entries = [];
  const line = "encryption_key: |";
  const out = redactConfigLine(line, 1, "f.yaml", entries);
  assert.strictEqual(out, line);
  assert.strictEqual(entries.length, 0);
});

// -----------------------------------------------------------------------
// PHASE 5 - directory walking for the File System Access API
// -----------------------------------------------------------------------
// collectFilesFromDirectoryHandle() is pure logic exercised here against
// tests/fake-fs-access.js's in-memory tree. It does NOT and CANNOT test
// the real browser APIs (showDirectoryPicker(), permission prompts) -
// those only exist in a real browser; see the final project summary for
// this distinction spelled out explicitly.

console.log("\ncollectFilesFromDirectoryHandle() - pure directory-walk logic:");

await test("flat directory: every file collected with its content", async () => {
  const dir = buildFakeDirectory({
    "config.json": '{"password": "fakeDirScan123"}',
    "readme.md": "hello",
  });
  const { files, skipped } = await collectFilesFromDirectoryHandle(dir);
  assert.strictEqual(files.length, 2);
  assert.strictEqual(skipped.length, 0);
  const configFile = files.find((f) => f.path === "config.json");
  assert.ok(configFile);
  assert.ok(configFile.content.includes("fakeDirScan123"));
});

await test("nested directories: paths built with '/' separators", async () => {
  const dir = buildFakeDirectory({
    src: { nested: { "deep.py": "password = 'fakeDeep123'" } },
    "top.env": "TOKEN=fakeTop456",
  });
  const { files } = await collectFilesFromDirectoryHandle(dir);
  const paths = files.map((f) => f.path).sort();
  assert.deepStrictEqual(paths, ["src/nested/deep.py", "top.env"]);
});

await test("SKIP_DIRS (e.g. node_modules, .git) are never descended into", async () => {
  const dir = buildFakeDirectory({
    "node_modules": { "somepkg.js": "should never appear" },
    ".git": { "config": "should never appear either" },
    "app.js": "const password = 'fakeSkipDirsTest';",
  });
  const { files } = await collectFilesFromDirectoryHandle(dir);
  assert.strictEqual(files.length, 1);
  assert.strictEqual(files[0].path, "app.js");
});

await test("binary-by-name files are skipped, not read", async () => {
  const dir = buildFakeDirectory({ "logo.png": "not real image bytes but shouldn't matter", "app.py": "x = 1" });
  const { files, skipped } = await collectFilesFromDirectoryHandle(dir, {
    isBinaryByName: (name) => name.toLowerCase().endsWith(".png"),
  });
  assert.strictEqual(files.length, 1);
  assert.deepStrictEqual(skipped, ["logo.png"]);
});

await test("oversized files are skipped, not read", async () => {
  const bigContent = "x".repeat(100);
  const dir = buildFakeDirectory({ "big.txt": bigContent, "small.txt": "ok" });
  const { files, skipped } = await collectFilesFromDirectoryHandle(dir, { maxFileBytes: 50 });
  assert.strictEqual(files.length, 1);
  assert.strictEqual(files[0].path, "small.txt");
  assert.deepStrictEqual(skipped, ["big.txt"]);
});

await test("end-to-end: files collected from a directory handle feed straight into scanFiles()", async () => {
  const dir = buildFakeDirectory({
    "app.properties": "password=fakeDirEndToEnd123",
    "config.json": '{\n  "api_key": "fakeDirJsonKey456"\n}',
  });
  const { files } = await collectFilesFromDirectoryHandle(dir);
  const { reportEntries, sanitizedFiles } = scanFiles(files);
  assert.strictEqual(reportEntries.length, 2);
  for (const f of sanitizedFiles) {
    assert.ok(!f.content.includes("fakeDirEndToEnd123"));
    assert.ok(!f.content.includes("fakeDirJsonKey456"));
  }
});

console.log("\n\"Scan again\" (Phase A) - persistent-handle fresh-read vs in-memory re-scan:");

await test("persistent-handle path: re-calling collectFilesFromDirectoryHandle() on the SAME handle picks up an on-disk edit", async () => {
  let currentContent = "api_key=fakeBeforeEdit111";
  const dir = buildFakeDirectory({ "app.properties": () => currentContent });

  const firstRead = await collectFilesFromDirectoryHandle(dir);
  assert.strictEqual(firstRead.files[0].content, "api_key=fakeBeforeEdit111");
  const firstScan = scanFiles(firstRead.files);
  assert.strictEqual(firstScan.reportEntries[0].before, "fakeBeforeEdit111");

  // Simulate an edit made to the file on disk, between the first and
  // second "scan" - a genuinely fresh read of the SAME handle must see it.
  currentContent = "api_key=fakeAfterEdit222";

  const secondRead = await collectFilesFromDirectoryHandle(dir);
  assert.strictEqual(secondRead.files[0].content, "api_key=fakeAfterEdit222", "the fresh re-read picked up the on-disk edit");
  const secondScan = scanFiles(secondRead.files);
  assert.strictEqual(secondScan.reportEntries[0].before, "fakeAfterEdit222");
});

await test("in-memory path: re-scanning the SAME already-loaded file contents never reflects a later edit (no re-read happens)", () => {
  // This models handleFileList()'s drag-and-drop/file-input path: content
  // is read into memory ONCE (readFileAsText(), outside the engine
  // entirely), and "Scan again" for this path just re-runs scanFiles() on
  // that same already-loaded array - there is no second read to pick up
  // an edit, unlike the persistent-handle path above. This is exactly the
  // property scanAgainSourceNote's disclosure text depends on being true.
  const inMemoryFiles = [{ path: "app.properties", content: "api_key=fakeLoadedOnce333" }];

  const firstScan = scanFiles(inMemoryFiles);
  assert.strictEqual(firstScan.reportEntries[0].before, "fakeLoadedOnce333");

  // The "file on disk" changes here, but nothing re-reads it - the
  // in-memory re-scan below can only ever see what's already in `inMemoryFiles`.
  const secondScan = scanFiles(inMemoryFiles); // "Scan again" on the same in-memory array
  assert.strictEqual(secondScan.reportEntries[0].before, "fakeLoadedOnce333", "still the original in-memory content - no fresh read occurred");
});

await test("\"Scan again\" preserves the filter selection: filterFilesByCheckedPaths() applied again with the SAME checkedPaths, not reset to everything", () => {
  const files = [
    { path: "keep/a.properties", content: "x" },
    { path: "exclude/b.properties", content: "y" },
  ];
  const checkedPaths = new Set(["keep/a.properties"]); // exclude/b.properties was unchecked before "Scan again"

  // First scan (already filtered).
  const firstFiltered = filterFilesByCheckedPaths(files, checkedPaths);
  assert.deepStrictEqual(firstFiltered.map((f) => f.path), ["keep/a.properties"]);

  // "Scan again" - same checkedPaths, reapplied to a fresh (here,
  // identical) file list, exactly as scanAgainBtn's handler does by never
  // touching checkedPaths itself.
  const secondFiltered = filterFilesByCheckedPaths(files, checkedPaths);
  assert.deepStrictEqual(secondFiltered.map((f) => f.path), ["keep/a.properties"], "selection preserved, not reset to everything checked");
});

// -----------------------------------------------------------------------
// PHASE 6 (checkpoint 1) - folder-filter tree: build, check-state, filter
// -----------------------------------------------------------------------

console.log("\nbuildFileTree() - flat path list -> nested tree:");

await test("flat, single-level files - all become direct children of root, folders-first-then-alpha ordering", () => {
  const tree = buildFileTree(["b.txt", "a.txt"]);
  assert.strictEqual(tree.type, "folder");
  assert.strictEqual(tree.path, "");
  assert.strictEqual(tree.children.length, 2);
  assert.deepStrictEqual(tree.children.map((c) => c.name), ["a.txt", "b.txt"]);
  assert.ok(tree.children.every((c) => c.type === "file"));
});

await test("nested paths create the correct folder hierarchy, deduplicated (not one folder node per file)", () => {
  const tree = buildFileTree(["src/app.py", "src/utils/helper.py", "src/utils/other.py", "README.md"]);
  assert.strictEqual(tree.children.length, 2, "src/ folder + README.md at top level");
  const [srcNode, readmeNode] = tree.children;
  assert.strictEqual(srcNode.type, "folder");
  assert.strictEqual(srcNode.path, "src");
  assert.strictEqual(readmeNode.type, "file");
  assert.strictEqual(readmeNode.path, "README.md");

  assert.strictEqual(srcNode.children.length, 2, "app.py + utils/ - not duplicated per file");
  const utilsNode = srcNode.children.find((c) => c.name === "utils");
  assert.strictEqual(utilsNode.type, "folder");
  assert.strictEqual(utilsNode.path, "src/utils");
  assert.strictEqual(utilsNode.children.length, 2);
  assert.deepStrictEqual(utilsNode.children.map((c) => c.path).sort(), ["src/utils/helper.py", "src/utils/other.py"]);
});

await test("folders sort before files at the same level, both alphabetically among themselves", () => {
  const tree = buildFileTree(["zzz.txt", "aaa_folder/inner.txt", "mmm.txt"]);
  assert.deepStrictEqual(tree.children.map((c) => c.name), ["aaa_folder", "mmm.txt", "zzz.txt"]);
});

await test("indexFileTree() finds any node (including root and nested folders) by exact path", () => {
  const tree = buildFileTree(["src/utils/helper.py"]);
  const index = indexFileTree(tree);
  assert.strictEqual(index.get(""), tree);
  assert.strictEqual(index.get("src").path, "src");
  assert.strictEqual(index.get("src/utils").path, "src/utils");
  assert.strictEqual(index.get("src/utils/helper.py").type, "file");
});

await test("collectFilePaths() returns every descendant file path, none of the folder paths themselves", () => {
  const tree = buildFileTree(["a/1.txt", "a/b/2.txt", "3.txt"]);
  assert.deepStrictEqual(collectFilePaths(tree).sort(), ["3.txt", "a/1.txt", "a/b/2.txt"]);
});

console.log("\ngetNodeCheckState()/setNodeChecked() - checkbox propagation:");

await test("a folder is 'checked' only when every descendant file is in checkedPaths", () => {
  const tree = buildFileTree(["a/1.txt", "a/2.txt"]);
  const aNode = indexFileTree(tree).get("a");
  assert.strictEqual(getNodeCheckState(aNode, new Set(["a/1.txt", "a/2.txt"])), "checked");
});

await test("a folder is 'unchecked' when none of its descendant files are in checkedPaths", () => {
  const tree = buildFileTree(["a/1.txt", "a/2.txt"]);
  const aNode = indexFileTree(tree).get("a");
  assert.strictEqual(getNodeCheckState(aNode, new Set()), "unchecked");
});

await test("a folder is 'indeterminate' when SOME but not all descendant files are checked", () => {
  const tree = buildFileTree(["a/1.txt", "a/2.txt", "a/3.txt"]);
  const aNode = indexFileTree(tree).get("a");
  assert.strictEqual(getNodeCheckState(aNode, new Set(["a/1.txt"])), "indeterminate");
});

await test("indeterminate propagates upward through multiple levels of nesting", () => {
  const tree = buildFileTree(["a/b/c/1.txt", "a/b/c/2.txt", "a/other.txt"]);
  const index = indexFileTree(tree);
  const checked = new Set(["a/b/c/1.txt"]); // only one of three total files under 'a'
  assert.strictEqual(getNodeCheckState(index.get("a/b/c"), checked), "indeterminate");
  assert.strictEqual(getNodeCheckState(index.get("a/b"), checked), "indeterminate");
  assert.strictEqual(getNodeCheckState(index.get("a"), checked), "indeterminate");
});

await test("checking a folder checks ALL of its descendants, regardless of their prior individual state", () => {
  const tree = buildFileTree(["a/1.txt", "a/2.txt", "a/b/3.txt"]);
  const aNode = indexFileTree(tree).get("a");
  const before = new Set(["a/1.txt"]); // 2.txt and b/3.txt currently unchecked
  const after = setNodeChecked(aNode, true, before);
  assert.deepStrictEqual([...after].sort(), ["a/1.txt", "a/2.txt", "a/b/3.txt"]);
  // Original Set passed in must be untouched (never mutated in place).
  assert.deepStrictEqual([...before], ["a/1.txt"]);
});

await test("unchecking a folder unchecks ALL of its descendants", () => {
  const tree = buildFileTree(["a/1.txt", "a/2.txt", "a/b/3.txt"]);
  const aNode = indexFileTree(tree).get("a");
  const before = new Set(["a/1.txt", "a/2.txt", "a/b/3.txt", "outside.txt"]);
  const after = setNodeChecked(aNode, false, before);
  assert.deepStrictEqual([...after], ["outside.txt"]);
});

await test("unchecking one file makes its parent folder indeterminate, not unchecked", () => {
  const tree = buildFileTree(["a/1.txt", "a/2.txt"]);
  const index = indexFileTree(tree);
  const fileNode = index.get("a/1.txt");
  const allChecked = new Set(["a/1.txt", "a/2.txt"]);
  const afterUncheckOne = setNodeChecked(fileNode, false, allChecked);
  assert.strictEqual(getNodeCheckState(index.get("a"), afterUncheckOne), "indeterminate");
});

await test("checking every individual file back makes the folder fully 'checked' again", () => {
  const tree = buildFileTree(["a/1.txt", "a/2.txt"]);
  const index = indexFileTree(tree);
  let checked = new Set(["a/1.txt"]);
  assert.strictEqual(getNodeCheckState(index.get("a"), checked), "indeterminate");
  checked = setNodeChecked(index.get("a/2.txt"), true, checked);
  assert.strictEqual(getNodeCheckState(index.get("a"), checked), "checked");
});

console.log("\nfilterFilesByCheckedPaths() - scan integration:");

await test("only checked paths are passed through, in their original order", () => {
  const files = [
    { path: "a.txt", content: "x" },
    { path: "b.txt", content: "y" },
    { path: "c.txt", content: "z" },
  ];
  const filtered = filterFilesByCheckedPaths(files, new Set(["a.txt", "c.txt"]));
  assert.deepStrictEqual(filtered.map((f) => f.path), ["a.txt", "c.txt"]);
});

await test("end-to-end: unchecking a folder in the tree actually excludes its files from scanFiles()", () => {
  const files = [
    { path: "keep/app.properties", content: "password=fakeKeepThis123" },
    { path: "exclude/secrets.properties", content: "api_key=fakeShouldNotAppear456" },
  ];
  const tree = buildFileTree(files.map((f) => f.path));
  const index = indexFileTree(tree);
  let checked = new Set(files.map((f) => f.path)); // everything checked by default
  checked = setNodeChecked(index.get("exclude"), false, checked);

  const filtered = filterFilesByCheckedPaths(files, checked);
  assert.strictEqual(filtered.length, 1);
  assert.strictEqual(filtered[0].path, "keep/app.properties");

  const { reportEntries, sanitizedFiles } = scanFiles(filtered);
  assert.strictEqual(reportEntries.length, 1, "the excluded file was never even handed to scanFiles()");
  assert.strictEqual(sanitizedFiles.length, 1);
  assert.strictEqual(sanitizedFiles[0].path, "keep/app.properties");
});

await test("SKIP_DIRS is exported and matches what scanFiles() itself actually skips (single source of truth for the tree to filter the same way)", () => {
  assert.ok(SKIP_DIRS.has("node_modules"));
  assert.ok(SKIP_DIRS.has(".git"));
  const files = [
    { path: "node_modules/pkg/index.js", content: "const password = 'shouldNeverBeScanned';" },
    { path: "app.js", content: "const password = 'fakeShouldBeScanned123';" },
  ];
  const { reportEntries } = scanFiles(files);
  assert.strictEqual(reportEntries.length, 1, "scanFiles() itself already skips SKIP_DIRS content");
});

// -----------------------------------------------------------------------
// Folder-filter tree (checkpoint 2) - reapplySavedSelection
// -----------------------------------------------------------------------

await test("reapplySavedSelection: a matched path that was checked before stays checked", () => {
  const result = reapplySavedSelection(
    ["a.txt", "b.txt"],
    ["a.txt", "b.txt"],
    ["a.txt", "b.txt"]
  );
  assert.deepStrictEqual([...result].sort(), ["a.txt", "b.txt"]);
});

await test("reapplySavedSelection: a matched path that was UNCHECKED before stays unchecked (not silently defaulted to checked)", () => {
  const result = reapplySavedSelection(
    ["a.txt", "b.txt"],
    ["a.txt", "b.txt"], // both existed before
    ["a.txt"]           // only a.txt was checked
  );
  assert.deepStrictEqual([...result], ["a.txt"]);
});

await test("reapplySavedSelection: a saved path that no longer exists is simply absent from the result", () => {
  const result = reapplySavedSelection(
    ["a.txt"], // b.txt no longer present this time
    ["a.txt", "b.txt"],
    ["a.txt", "b.txt"]
  );
  assert.deepStrictEqual([...result], ["a.txt"]);
});

await test("reapplySavedSelection: a genuinely new path (never seen in the saved selection) defaults to checked", () => {
  const result = reapplySavedSelection(
    ["a.txt", "new.txt"],
    ["a.txt"],
    ["a.txt"]
  );
  assert.deepStrictEqual([...result].sort(), ["a.txt", "new.txt"]);
});

await test("reapplySavedSelection: mixed matched/missing/new paths all resolve independently in one call", () => {
  const result = reapplySavedSelection(
    ["kept-checked.txt", "kept-unchecked.txt", "brand-new.txt"], // missing.txt absent this time
    ["kept-checked.txt", "kept-unchecked.txt", "missing.txt"],
    ["kept-checked.txt", "missing.txt"]
  );
  assert.deepStrictEqual([...result].sort(), ["brand-new.txt", "kept-checked.txt"]);
});

await test("reapplySavedSelection: never mutates any of its input arrays", () => {
  const currentPaths = ["a.txt", "b.txt"];
  const savedAllPaths = ["a.txt", "b.txt"];
  const savedCheckedPaths = ["a.txt"];
  reapplySavedSelection(currentPaths, savedAllPaths, savedCheckedPaths);
  assert.deepStrictEqual(currentPaths, ["a.txt", "b.txt"]);
  assert.deepStrictEqual(savedAllPaths, ["a.txt", "b.txt"]);
  assert.deepStrictEqual(savedCheckedPaths, ["a.txt"]);
});

await test("reapplySavedSelection: an empty saved selection (first-ever visit) defaults every current path to checked", () => {
  const result = reapplySavedSelection(["a.txt", "b.txt"], [], []);
  assert.deepStrictEqual([...result].sort(), ["a.txt", "b.txt"]);
});

// -----------------------------------------------------------------------

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
}

main();
