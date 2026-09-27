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
} = require(path.join(__dirname, "..", "scanner-engine.js"));

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ok  - ${name}`);
  } catch (e) {
    failed++;
    console.log(`FAIL  - ${name}`);
    console.log(`        ${e.message}`);
  }
}

// -----------------------------------------------------------------------
// PHASE 1 - multi-line concatenated secret detection
// -----------------------------------------------------------------------

console.log("Python parenthesized concatenation:");

test("basic two-fragment concatenation is masked, both fragments gone", () => {
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

test("three-fragment concatenation - every fragment masked, line count unchanged", () => {
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

test("no closing paren - left untouched (malformed, not guessed at)", () => {
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

test("harmless variable name + non-sensitive value - not flagged", () => {
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

test("Java trailing-+ style masks every fragment", () => {
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

test("JavaScript trailing-+ style (const declaration) is masked", () => {
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

test("C# trailing-+ style (string declaration) is masked", () => {
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

test("three-fragment trailing-+ chain - all three fragments masked", () => {
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

test("Java leading-+ style masks every fragment", () => {
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

test("leading-+ chain with three fragments, terminated by ';' on the last", () => {
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

test("trailing-+ chain with no terminating ';' is left untouched entirely", () => {
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

test("single fragment only (no real concatenation) is not treated as multiline", () => {
  const lines = [
    'String authToken = "fake1234";', // already terminated on line 1, no continuation
    "int x = 5;",
  ];
  const entries = [];
  scanMultilinePlus(lines, "f.java", entries);
  assert.strictEqual(entries.length, 0);
});

console.log("\nGo parity (intentionally NOT covered, matching engine.py):");

test("Go '+' concatenation is not detected (matches desktop's known limitation)", () => {
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

test("scanFiles(): Python file with both a multiline secret and a single-line secret - both caught, no double-processing", () => {
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

test("scanFiles(): Java file with a multiline secret - sanitized output never contains the real value", () => {
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

test("config key-name match still redacts (password=)", () => {
  const entries = [];
  const out = redactConfigLine("password=fakeSup3rSecret!", 1, "f.env", entries);
  assert.ok(out.includes(MASK));
  assert.strictEqual(entries.length, 1);
  assert.strictEqual(entries[0].rule, "key_name_match");
});

test("config: ordinary non-secret value untouched", () => {
  const entries = [];
  const out = redactConfigLine("region=us-east-1", 1, "f.env", entries);
  assert.strictEqual(out, "region=us-east-1");
  assert.strictEqual(entries.length, 0);
});

test("config: placeholder allow-list still suppresses a value-only match", () => {
  const entries = [];
  const out = redactConfigLine("some_value=localhost", 1, "f.env", entries);
  assert.strictEqual(entries.length, 0);
  assert.strictEqual(out, "some_value=localhost");
});

test("value-pattern: AWS access key id still detected in free text", () => {
  const entries = [];
  const out = redactValuePatternsOnly("key = AKIAABCDEFGHIJKLMNOP", 1, "f.txt", entries);
  assert.ok(out.includes(MASK));
  assert.strictEqual(entries[0].rule, "aws_access_key_id");
});

test("value-pattern: JWT still detected", () => {
  const entries = [];
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ";
  const out = redactValuePatternsOnly(`token: ${jwt}`, 1, "f.txt", entries);
  assert.ok(out.includes(MASK));
  assert.strictEqual(entries[0].rule, "jwt_token");
});

test("code: single-line Java secret literal still detected (unrelated to multiline change)", () => {
  const entries = [];
  const out = redactCodeLine('String password = "fakeSingleLine123";', "java", 1, "f.java", entries);
  assert.ok(!out.includes("fakeSingleLine123"));
  assert.strictEqual(entries.length, 1);
});

test("findKeyMatches(): camelCase-aware - 'authToken' matches, 'author' does not", () => {
  assert.strictEqual(findKeyMatches("authToken"), true);
  assert.strictEqual(findKeyMatches("author"), false);
});

test("findKeyMatches(): 'dbPassword' matches via camelCase transition", () => {
  assert.strictEqual(findKeyMatches("dbPassword"), true);
});

test("findKeyMatches(): a harmless variable name does not match", () => {
  assert.strictEqual(findKeyMatches("message"), false);
});

// -----------------------------------------------------------------------
// Data-driven rules sync (rules-data.js, generated from rules_default.yaml)
// -----------------------------------------------------------------------

console.log("\nData-driven rules sync (rules-data.js):");

test("config: 'username' is no longer a key pattern (matches current rules_default.yaml)", () => {
  const entries = [];
  const out = redactConfigLine("username=admin", 1, "f.env", entries);
  assert.strictEqual(entries.length, 0, "username should not be flagged - it was removed from rules_default.yaml");
  assert.strictEqual(out, "username=admin");
});

test("config: 'port' is no longer a key pattern (matches current rules_default.yaml)", () => {
  const entries = [];
  const out = redactConfigLine("port=5432", 1, "f.env", entries);
  assert.strictEqual(entries.length, 0, "port should not be flagged - it was removed from rules_default.yaml");
  assert.strictEqual(out, "port=5432");
});

test("config: 'db_port' still fine (not a real secret either, and 'port' isn't a pattern anymore anyway)", () => {
  const entries = [];
  redactConfigLine("db_port=5432", 1, "f.env", entries);
  assert.strictEqual(entries.length, 0);
});

test("bonus fix from switching to strict uniform boundary checking: 'secretary_name' no longer falsely matches bare 'secret'", () => {
  const entries = [];
  const out = redactConfigLine("secretary_name = John Smith", 1, "f.env", entries);
  assert.strictEqual(entries.length, 0, "'secret' must not match as a substring of 'secretary'");
  assert.strictEqual(out, "secretary_name = John Smith");
});

test("uniform boundary checking still correctly matches genuine keys sharing a word boundary with 'secret'", () => {
  const entries = [];
  const out = redactConfigLine("client_secret=fakeSecretValue123", 1, "f.env", entries);
  assert.ok(out.includes(MASK));
  assert.strictEqual(entries.length, 1);
});

test("bonus coverage gained from data-driven code_patterns: Python os.getenv(...) fallback default is now detected", () => {
  const entries = [];
  const out = redactCodeLine('DB_PASSWORD = os.getenv("DB_PASSWORD", "fake-PlainOldPassword1")', "python", 1, "f.py", entries);
  assert.ok(!out.includes("fake-PlainOldPassword1"), "the hardcoded fallback default should be masked");
  assert.ok(entries.length >= 1);
});

// -----------------------------------------------------------------------

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
