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
  getRuleOverrides, saveRuleOverrides, resetRuleOverrides,
  saveFolderHandle, getFolderHandle, clearFolderHandle,
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

console.log("\nRule overrides (Phase 4):");

await test("getRuleOverrides() returns an empty override set when nothing has been saved yet", async () => {
  resetFakeIndexedDB();
  const db = await openScannerDB();
  const overrides = await getRuleOverrides(db);
  assert.deepStrictEqual(overrides.keyPatternsAdded, []);
  assert.deepStrictEqual(overrides.keyPatternsRemoved, []);
  assert.deepStrictEqual(overrides.placeholderAllowlistAdded, []);
  assert.deepStrictEqual(overrides.placeholderAllowlistRemoved, []);
});

await test("saveRuleOverrides() + getRuleOverrides() round-trips a full override set", async () => {
  resetFakeIndexedDB();
  const db = await openScannerDB();
  await saveRuleOverrides(db, {
    keyPatternsAdded: ["totallycustomsecret"],
    keyPatternsRemoved: ["password"],
    placeholderAllowlistAdded: ["myteamtoken"],
    placeholderAllowlistRemoved: [],
  });
  const overrides = await getRuleOverrides(db);
  assert.deepStrictEqual(overrides.keyPatternsAdded, ["totallycustomsecret"]);
  assert.deepStrictEqual(overrides.keyPatternsRemoved, ["password"]);
  assert.deepStrictEqual(overrides.placeholderAllowlistAdded, ["myteamtoken"]);
});

await test("saveRuleOverrides() overwrites the previous saved set (single record, not appended)", async () => {
  resetFakeIndexedDB();
  const db = await openScannerDB();
  await saveRuleOverrides(db, { keyPatternsAdded: ["first"], keyPatternsRemoved: [] });
  await saveRuleOverrides(db, { keyPatternsAdded: ["second"], keyPatternsRemoved: [] });
  const overrides = await getRuleOverrides(db);
  assert.deepStrictEqual(overrides.keyPatternsAdded, ["second"]);
});

await test("resetRuleOverrides() returns to the empty (base-only) state", async () => {
  resetFakeIndexedDB();
  const db = await openScannerDB();
  await saveRuleOverrides(db, { keyPatternsAdded: ["custom"], keyPatternsRemoved: [] });
  await resetRuleOverrides(db);
  const overrides = await getRuleOverrides(db);
  assert.deepStrictEqual(overrides.keyPatternsAdded, []);
});

await test("rule overrides persist after closing and reopening the 'tab'", async () => {
  resetFakeIndexedDB();
  const dbBeforeClose = await openScannerDB();
  await saveRuleOverrides(dbBeforeClose, { keyPatternsAdded: ["custom"], keyPatternsRemoved: ["password"] });
  const dbAfterReopen = await openScannerDB();
  const overrides = await getRuleOverrides(dbAfterReopen);
  assert.deepStrictEqual(overrides.keyPatternsAdded, ["custom"]);
  assert.deepStrictEqual(overrides.keyPatternsRemoved, ["password"]);
});

console.log("\nDatabase migration (simulating an existing Phase 3 user upgrading to Phase 4):");

await test("an existing v1 database (scanHistory + ignores only) upgrades to v2 without losing data, and gains a working ruleOverrides store", async () => {
  resetFakeIndexedDB();

  // Manually open at v1 with ONLY the two Phase-3 stores, exactly as an
  // existing user's browser would already have on disk - bypassing
  // storage.js's own openScannerDB() (which always requests the CURRENT
  // version) so this test can start from a genuinely older schema.
  const dbV1 = await new Promise((resolve, reject) => {
    const req = indexedDB.open("credential-scrubber-scanner", 1);
    req.onupgradeneeded = (event) => {
      const db = event.target.result;
      db.createObjectStore("scanHistory", { keyPath: "id", autoIncrement: true });
      db.createObjectStore("ignores", { keyPath: "ignoreKey" });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  await new Promise((resolve, reject) => {
    const tx = dbV1.transaction("scanHistory", "readwrite");
    const r = tx.objectStore("scanHistory").add({ timestamp: Date.now(), fileCount: 2, findingCount: 1, entries: [] });
    r.onsuccess = () => resolve();
    r.onerror = () => reject(r.error);
  });

  // Now the page loads Phase 4's code, which calls storage.js's
  // openScannerDB() - requesting the CURRENT version (2).
  const dbV2 = await openScannerDB();
  const history = await listScanHistory(dbV2);
  assert.strictEqual(history.length, 1, "the pre-existing Phase 3 scan history survived the upgrade");
  assert.strictEqual(history[0].fileCount, 2);

  // And the new store actually works, not just exists.
  await saveRuleOverrides(dbV2, { keyPatternsAdded: ["custom"], keyPatternsRemoved: [] });
  const overrides = await getRuleOverrides(dbV2);
  assert.deepStrictEqual(overrides.keyPatternsAdded, ["custom"]);
});

console.log("\nRemembered folder handle (Phase 5):");

await test("getFolderHandle() returns null when nothing has been saved yet", async () => {
  resetFakeIndexedDB();
  const db = await openScannerDB();
  const record = await getFolderHandle(db);
  assert.strictEqual(record, null);
});

await test("saveFolderHandle() + getFolderHandle() round-trips the handle object and its display name", async () => {
  resetFakeIndexedDB();
  const db = await openScannerDB();
  const fakeHandle = { kind: "directory", name: "my-project" }; // stand-in for a real FileSystemDirectoryHandle
  await saveFolderHandle(db, fakeHandle, "my-project");
  const record = await getFolderHandle(db);
  assert.strictEqual(record.name, "my-project");
  assert.deepStrictEqual(record.handle, fakeHandle);
});

await test("saveFolderHandle() overwrites the previously remembered folder (single record, not a list)", async () => {
  resetFakeIndexedDB();
  const db = await openScannerDB();
  await saveFolderHandle(db, { kind: "directory", name: "first" }, "first");
  await saveFolderHandle(db, { kind: "directory", name: "second" }, "second");
  const record = await getFolderHandle(db);
  assert.strictEqual(record.name, "second");
});

await test("clearFolderHandle() forgets the remembered folder", async () => {
  resetFakeIndexedDB();
  const db = await openScannerDB();
  await saveFolderHandle(db, { kind: "directory", name: "x" }, "x");
  await clearFolderHandle(db);
  assert.strictEqual(await getFolderHandle(db), null);
});

await test("remembered folder persists after closing and reopening the 'tab'", async () => {
  resetFakeIndexedDB();
  const dbBeforeClose = await openScannerDB();
  await saveFolderHandle(dbBeforeClose, { kind: "directory", name: "persisted" }, "persisted");
  const dbAfterReopen = await openScannerDB();
  const record = await getFolderHandle(dbAfterReopen);
  assert.strictEqual(record.name, "persisted");
});

await test("an existing v2 database (no folderHandle store) upgrades to v3 without losing data, and gains a working folderHandle store", async () => {
  resetFakeIndexedDB();

  // Manually open at v2 with only the three Phase 3/4 stores, exactly as
  // an existing user's browser would already have on disk.
  const dbV2 = await new Promise((resolve, reject) => {
    const req = indexedDB.open("credential-scrubber-scanner", 2);
    req.onupgradeneeded = (event) => {
      const db = event.target.result;
      db.createObjectStore("scanHistory", { keyPath: "id", autoIncrement: true });
      db.createObjectStore("ignores", { keyPath: "ignoreKey" });
      db.createObjectStore("ruleOverrides", { keyPath: "id" });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  await new Promise((resolve, reject) => {
    const tx = dbV2.transaction("ruleOverrides", "readwrite");
    const r = tx.objectStore("ruleOverrides").put({ id: "default", keyPatternsAdded: ["preexisting"], keyPatternsRemoved: [] });
    r.onsuccess = () => resolve();
    r.onerror = () => reject(r.error);
  });

  // Phase 5's code loads and calls storage.js's openScannerDB() - now
  // requesting v3.
  const dbV3 = await openScannerDB();
  const overrides = await getRuleOverrides(dbV3);
  assert.deepStrictEqual(overrides.keyPatternsAdded, ["preexisting"], "pre-existing Phase 4 rule overrides survived the upgrade");

  await saveFolderHandle(dbV3, { kind: "directory", name: "new-store-works" }, "new-store-works");
  const record = await getFolderHandle(dbV3);
  assert.strictEqual(record.name, "new-store-works");
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;

}

main();
