/**
 * Plain Node.js test script for scanner/storage.js. Uses
 * tests/fake-indexeddb.js (local test infrastructure, not a dependency)
 * to exercise storage.js's real IndexedDB-calling code under Node, which
 * has no native IndexedDB. Run with:
 *
 *     node tests/storage.test.js
 */

const assert = require("assert");
const path = require("path");
const { installFakeIndexedDB, resetFakeIndexedDB } = require(path.join(__dirname, "fake-indexeddb.js"));

installFakeIndexedDB();

const {
  openScannerDB, ignoreKeyFor,
  saveScanHistoryEntry, listScanHistory, clearScanHistory,
  setIgnore, removeIgnore, getIgnoreMap,
} = require(path.join(__dirname, "..", "scanner", "storage.js"));

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ok  - ${name}`);
  } catch (e) {
    failed++;
    console.log(`FAIL  - ${name}`);
    console.log(`        ${e.stack || e.message}`);
  }
}

async function main() {

console.log("Scan history:");

await test("saveScanHistoryEntry() + listScanHistory() round-trips a record", async () => {
  resetFakeIndexedDB();
  const db = await openScannerDB();
  await saveScanHistoryEntry(db, {
    fileCount: 3,
    findingCount: 2,
    entries: [
      { file: "a.env", line: 1, rule: "key_name_match", key: "password" },
      { file: "b.properties", line: 4, rule: "aws_access_key_id", key: null },
    ],
  });
  const history = await listScanHistory(db);
  assert.strictEqual(history.length, 1);
  assert.strictEqual(history[0].fileCount, 3);
  assert.strictEqual(history[0].findingCount, 2);
  assert.strictEqual(history[0].entries.length, 2);
  // Never stores raw values - only file/line/rule/key.
  assert.strictEqual(Object.prototype.hasOwnProperty.call(history[0].entries[0], "before"), false);
  assert.strictEqual(Object.prototype.hasOwnProperty.call(history[0].entries[0], "after"), false);
});

await test("scan history persists after closing and reopening the 'tab' (simulated: fresh openScannerDB() call, same backing data)", async () => {
  resetFakeIndexedDB();
  const dbBeforeClose = await openScannerDB();
  await saveScanHistoryEntry(dbBeforeClose, { fileCount: 1, findingCount: 1, entries: [{ file: "x.env", line: 1, rule: "key_name_match", key: "password" }] });
  await saveScanHistoryEntry(dbBeforeClose, { fileCount: 5, findingCount: 0, entries: [] });
  // Simulate the tab closing (drop every JS reference to the old
  // connection) and reopening (a brand-new openScannerDB() call, exactly
  // what the page does on load) - note resetFakeIndexedDB() is NOT called
  // here, since a real browser tab closing does not erase IndexedDB.
  const dbAfterReopen = await openScannerDB();
  const history = await listScanHistory(dbAfterReopen);
  assert.strictEqual(history.length, 2, "both scans from the 'previous session' are still there");
});

await test("listScanHistory() returns newest first", async () => {
  resetFakeIndexedDB();
  const db = await openScannerDB();
  await saveScanHistoryEntry(db, { fileCount: 1, findingCount: 1, entries: [] });
  await new Promise((r) => setTimeout(r, 5));
  await saveScanHistoryEntry(db, { fileCount: 2, findingCount: 2, entries: [] });
  const history = await listScanHistory(db);
  assert.strictEqual(history[0].fileCount, 2, "most recent scan first");
  assert.strictEqual(history[1].fileCount, 1);
});

await test("clearScanHistory() empties the store", async () => {
  resetFakeIndexedDB();
  const db = await openScannerDB();
  await saveScanHistoryEntry(db, { fileCount: 1, findingCount: 1, entries: [] });
  await clearScanHistory(db);
  const history = await listScanHistory(db);
  assert.strictEqual(history.length, 0);
});

console.log("\nIgnore list:");

await test("setIgnore() + getIgnoreMap() round-trips a hash, keyed the same way applyIgnores() expects", async () => {
  resetFakeIndexedDB();
  const db = await openScannerDB();
  await setIgnore(db, "app.properties", "api_key", "key_name_match", "deadbeef");
  const map = await getIgnoreMap(db);
  const key = ignoreKeyFor("app.properties", "api_key", "key_name_match");
  assert.strictEqual(map[key], "deadbeef");
});

await test("setIgnore() with the same (file,key,rule) overwrites the stored hash (value was re-ignored after rotating)", async () => {
  resetFakeIndexedDB();
  const db = await openScannerDB();
  await setIgnore(db, "app.properties", "api_key", "key_name_match", "oldhash");
  await setIgnore(db, "app.properties", "api_key", "key_name_match", "newhash");
  const map = await getIgnoreMap(db);
  assert.strictEqual(map[ignoreKeyFor("app.properties", "api_key", "key_name_match")], "newhash");
});

await test("removeIgnore() un-ignores a finding", async () => {
  resetFakeIndexedDB();
  const db = await openScannerDB();
  await setIgnore(db, "app.properties", "api_key", "key_name_match", "somehash");
  await removeIgnore(db, "app.properties", "api_key", "key_name_match");
  const map = await getIgnoreMap(db);
  assert.strictEqual(Object.prototype.hasOwnProperty.call(map, ignoreKeyFor("app.properties", "api_key", "key_name_match")), false);
});

await test("ignore list persists after closing and reopening the 'tab'", async () => {
  resetFakeIndexedDB();
  const dbBeforeClose = await openScannerDB();
  await setIgnore(dbBeforeClose, "a.env", "password", "key_name_match", "hash1");
  const dbAfterReopen = await openScannerDB();
  const map = await getIgnoreMap(dbAfterReopen);
  assert.strictEqual(map[ignoreKeyFor("a.env", "password", "key_name_match")], "hash1");
});

await test("resetFakeIndexedDB() (simulating cleared browser data) actually wipes everything - sanity check on the test double itself", async () => {
  resetFakeIndexedDB();
  const db = await openScannerDB();
  await setIgnore(db, "a.env", "password", "key_name_match", "hash1");
  await saveScanHistoryEntry(db, { fileCount: 1, findingCount: 1, entries: [] });
  resetFakeIndexedDB();
  const dbAfterClear = await openScannerDB();
  assert.deepStrictEqual(await getIgnoreMap(dbAfterClear), {});
  assert.deepStrictEqual(await listScanHistory(dbAfterClear), []);
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;

}

main();
