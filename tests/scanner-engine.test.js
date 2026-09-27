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
  hashValue, ignoreKeyFor, applyIgnores, replaceNthOccurrence,
  computeEffectiveKeyPatterns, computeEffectivePlaceholderAllowlist, getBaseRuleSnapshot,
  findKeyValue, quoteWrap, classifyFile,
} = require(path.join(__dirname, "..", "scanner-engine.js"));

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

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
}

main();
