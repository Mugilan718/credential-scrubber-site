/**
 * storage.js
 * Local-only persistence for the browser scanner, via IndexedDB.
 *
 * IMPORTANT: everything stored here lives ONLY in this one browser, on
 * this one device. It never syncs anywhere, is never sent over the
 * network, and is lost if the browser's site data for this page is
 * cleared. There is no server-side component.
 *
 * Three object stores:
 *   - "scanHistory": one record per completed scan - timestamp, file/
 *     finding counts, and a SAFE report (file/line/rule/key only - never
 *     the raw "before"/"after" values) by default.
 *   - "ignores": one record per ignored finding, identified by
 *     (file, key, rule) - storing only a SHA-256 HASH of the value at the
 *     moment it was ignored, never the value itself. See
 *     scanner-engine.js's hashValue()/applyIgnores() for how this hash is
 *     computed and checked on a later scan.
 *   - "ruleOverrides" (Phase 4): a single record holding this browser's
 *     local additions/removals to key_patterns and placeholder_allowlist -
 *     never the base rules themselves. See scanner-engine.js's
 *     computeEffectiveKeyPatterns()/computeEffectivePlaceholderAllowlist()
 *     for how these are layered on top of window.RULES/rules-data.js
 *     without ever modifying it.
 *   - "folderHandle" (Phase 5): a single record holding a remembered
 *     FileSystemDirectoryHandle (structured-cloneable, so IndexedDB can
 *     store the handle itself, not just its name) - lets a user re-scan a
 *     folder on a later visit without re-selecting it. Chromium-only (the
 *     File System Access API); see scanner-ui.js for the feature-detection
 *     and graceful-degradation handling on browsers without it.
 *
 * This file contains no detection/redaction logic of its own - it is a
 * thin CRUD wrapper around IndexedDB. The logic that decides whether an
 * ignored finding should stay suppressed or reappear (hash comparison,
 * text restoration), and how rule overrides merge with the base ruleset,
 * lives in scanner-engine.js, which is pure and unit-tested under plain
 * Node; this file's IndexedDB calls can only be exercised in a real
 * browser (or the fake IndexedDB test double used by tests/storage.test.js).
 *
 * DB_VERSION history: 1 (Phase 3 - scanHistory, ignores), 2 (Phase 4 -
 * adds ruleOverrides), 3 (Phase 5 - adds folderHandle). Bumping this
 * version is what makes an existing user's browser add the new store on
 * next load via onupgradeneeded, WITHOUT touching their existing data.
 */

const DB_NAME = "credential-scrubber-scanner";
const DB_VERSION = 3;
const SCAN_HISTORY_STORE = "scanHistory";
const IGNORES_STORE = "ignores";
const RULE_OVERRIDES_STORE = "ruleOverrides";
const RULE_OVERRIDES_ID = "default"; // single record - this is per-browser session config, not a list
const FOLDER_HANDLE_STORE = "folderHandle";
const FOLDER_HANDLE_ID = "default"; // single record - one remembered folder at a time

function promisifyRequest(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function openScannerDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(SCAN_HISTORY_STORE)) {
        db.createObjectStore(SCAN_HISTORY_STORE, { keyPath: "id", autoIncrement: true });
      }
      if (!db.objectStoreNames.contains(IGNORES_STORE)) {
        db.createObjectStore(IGNORES_STORE, { keyPath: "ignoreKey" });
      }
      if (!db.objectStoreNames.contains(RULE_OVERRIDES_STORE)) {
        db.createObjectStore(RULE_OVERRIDES_STORE, { keyPath: "id" });
      }
      if (!db.objectStoreNames.contains(FOLDER_HANDLE_STORE)) {
        db.createObjectStore(FOLDER_HANDLE_STORE, { keyPath: "id" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

// Kept in sync with scanner-engine.js's ignoreKeyFor() - duplicated rather
// than cross-required, since both files load as plain <script> tags in the
// browser with no module system; the format is a one-line, stable
// convention ((file, key, rule) joined with a NUL separator), not
// business logic that's likely to drift.
function ignoreKeyFor(file, key, rule) {
  return `${file}\u0000${key || ""}\u0000${rule}`;
}

/**
 * Save one completed scan as a scan-history record. `summary.entries`
 * should already be trimmed to {file, line, rule, key} only - this
 * function does not itself strip "before"/"after", so callers control
 * exactly what gets persisted (kept explicit and visible at the call
 * site, rather than a silent internal filter here).
 */
async function saveScanHistoryEntry(db, summary) {
  const tx = db.transaction(SCAN_HISTORY_STORE, "readwrite");
  const record = {
    timestamp: Date.now(),
    fileCount: summary.fileCount,
    findingCount: summary.findingCount,
    entries: summary.entries,
  };
  await promisifyRequest(tx.objectStore(SCAN_HISTORY_STORE).add(record));
  return record;
}

async function listScanHistory(db) {
  const tx = db.transaction(SCAN_HISTORY_STORE, "readonly");
  const all = await promisifyRequest(tx.objectStore(SCAN_HISTORY_STORE).getAll());
  return all.slice().sort((a, b) => b.timestamp - a.timestamp);
}

async function clearScanHistory(db) {
  const tx = db.transaction(SCAN_HISTORY_STORE, "readwrite");
  await promisifyRequest(tx.objectStore(SCAN_HISTORY_STORE).clear());
}

async function setIgnore(db, file, key, rule, hash) {
  const tx = db.transaction(IGNORES_STORE, "readwrite");
  const record = { ignoreKey: ignoreKeyFor(file, key, rule), file, key: key || null, rule, hash, ignoredAt: Date.now() };
  await promisifyRequest(tx.objectStore(IGNORES_STORE).put(record));
  return record;
}

async function removeIgnore(db, file, key, rule) {
  const tx = db.transaction(IGNORES_STORE, "readwrite");
  await promisifyRequest(tx.objectStore(IGNORES_STORE).delete(ignoreKeyFor(file, key, rule)));
}

/** Returns { [ignoreKeyFor(file,key,rule)]: hash } - what applyIgnores() expects. */
async function getIgnoreMap(db) {
  const tx = db.transaction(IGNORES_STORE, "readonly");
  const all = await promisifyRequest(tx.objectStore(IGNORES_STORE).getAll());
  const map = {};
  for (const record of all) {
    map[record.ignoreKey] = record.hash;
  }
  return map;
}

const EMPTY_OVERRIDES = Object.freeze({
  id: RULE_OVERRIDES_ID,
  keyPatternsAdded: [],
  keyPatternsRemoved: [],
  placeholderAllowlistAdded: [],
  placeholderAllowlistRemoved: [],
});

/** Returns the current local overrides, or an empty set if none saved yet. */
async function getRuleOverrides(db) {
  const tx = db.transaction(RULE_OVERRIDES_STORE, "readonly");
  const record = await promisifyRequest(tx.objectStore(RULE_OVERRIDES_STORE).get(RULE_OVERRIDES_ID));
  return record || { ...EMPTY_OVERRIDES };
}

/**
 * Replaces the stored overrides wholesale. Callers pass the FULL, already-
 * merged {keyPatternsAdded, keyPatternsRemoved, placeholderAllowlistAdded,
 * placeholderAllowlistRemoved} - this function does not itself merge with
 * whatever was there before, so the call site stays in full control of
 * what's persisted (same explicitness convention as saveScanHistoryEntry).
 */
async function saveRuleOverrides(db, overrides) {
  const tx = db.transaction(RULE_OVERRIDES_STORE, "readwrite");
  const record = { ...EMPTY_OVERRIDES, ...overrides, id: RULE_OVERRIDES_ID };
  await promisifyRequest(tx.objectStore(RULE_OVERRIDES_STORE).put(record));
  return record;
}

/** Back to the shared base ruleset only - removes this browser's local edits entirely. */
async function resetRuleOverrides(db) {
  const tx = db.transaction(RULE_OVERRIDES_STORE, "readwrite");
  await promisifyRequest(tx.objectStore(RULE_OVERRIDES_STORE).delete(RULE_OVERRIDES_ID));
}

/**
 * Remembers a FileSystemDirectoryHandle (Phase 5) - the handle object
 * itself, not just its name, so a later visit can re-request permission
 * and re-read the same folder without the user picking it again. `name`
 * is stored alongside purely for display ("Scan remembered folder: X")
 * without needing to touch the handle just to show its name.
 */
async function saveFolderHandle(db, handle, name) {
  const tx = db.transaction(FOLDER_HANDLE_STORE, "readwrite");
  const record = { id: FOLDER_HANDLE_ID, handle, name, savedAt: Date.now() };
  await promisifyRequest(tx.objectStore(FOLDER_HANDLE_STORE).put(record));
  return record;
}

/** Returns the remembered { handle, name } record, or null if none saved. */
async function getFolderHandle(db) {
  const tx = db.transaction(FOLDER_HANDLE_STORE, "readonly");
  const record = await promisifyRequest(tx.objectStore(FOLDER_HANDLE_STORE).get(FOLDER_HANDLE_ID));
  return record || null;
}

async function clearFolderHandle(db) {
  const tx = db.transaction(FOLDER_HANDLE_STORE, "readwrite");
  await promisifyRequest(tx.objectStore(FOLDER_HANDLE_STORE).delete(FOLDER_HANDLE_ID));
}

const ScannerStorage = {
  openScannerDB, ignoreKeyFor,
  saveScanHistoryEntry, listScanHistory, clearScanHistory,
  setIgnore, removeIgnore, getIgnoreMap,
  getRuleOverrides, saveRuleOverrides, resetRuleOverrides,
  saveFolderHandle, getFolderHandle, clearFolderHandle,
};

if (typeof window !== "undefined") {
  window.ScannerStorage = ScannerStorage;
}
if (typeof module !== "undefined") {
  module.exports = ScannerStorage;
}
