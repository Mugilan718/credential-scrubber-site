/**
 * storage.js
 * Local-only persistence for the browser scanner, via IndexedDB.
 *
 * IMPORTANT: everything stored here lives ONLY in this one browser, on
 * this one device. It never syncs anywhere, is never sent over the
 * network, and is lost if the browser's site data for this page is
 * cleared. There is no server-side component.
 *
 * Two object stores:
 *   - "scanHistory": one record per completed scan - timestamp, file/
 *     finding counts, and a SAFE report (file/line/rule/key only - never
 *     the raw "before"/"after" values) by default.
 *   - "ignores": one record per ignored finding, identified by
 *     (file, key, rule) - storing only a SHA-256 HASH of the value at the
 *     moment it was ignored, never the value itself. See
 *     scanner-engine.js's hashValue()/applyIgnores() for how this hash is
 *     computed and checked on a later scan.
 *
 * This file contains no detection/redaction logic of its own - it is a
 * thin CRUD wrapper around IndexedDB. The logic that decides whether an
 * ignored finding should stay suppressed or reappear (hash comparison,
 * text restoration) lives in scanner-engine.js's applyIgnores(), which is
 * pure and unit-tested under plain Node; this file's IndexedDB calls can
 * only be exercised in a real browser (or the fake IndexedDB test double
 * used by tests/storage.test.js).
 */

const DB_NAME = "credential-scrubber-scanner";
const DB_VERSION = 1;
const SCAN_HISTORY_STORE = "scanHistory";
const IGNORES_STORE = "ignores";

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

const ScannerStorage = {
  openScannerDB, ignoreKeyFor,
  saveScanHistoryEntry, listScanHistory, clearScanHistory,
  setIgnore, removeIgnore, getIgnoreMap,
};

if (typeof window !== "undefined") {
  window.ScannerStorage = ScannerStorage;
}
if (typeof module !== "undefined") {
  module.exports = ScannerStorage;
}
