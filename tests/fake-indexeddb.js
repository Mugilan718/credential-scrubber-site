/**
 * A minimal, purpose-built fake of the small subset of the IndexedDB API
 * that storage.js actually uses (open/onupgradeneeded, createObjectStore,
 * transaction, add/put/get All/delete/clear). This is NOT a dependency -
 * it's local test infrastructure written for this repo, so storage.js's
 * real code can be exercised under plain Node (which has no IndexedDB)
 * without adding an npm package.
 *
 * Crucially, the backing data lives at MODULE scope (`databases` below),
 * not per-connection - so calling installFakeIndexedDB() again and
 * re-opening the same database name in a later test simulates a browser
 * tab being closed and reopened: the same on-disk data is still there,
 * exactly as real IndexedDB would behave, because nothing in this file
 * throws it away between "connections."
 *
 * Call resetFakeIndexedDB() explicitly in a test if you want to simulate
 * the data being wiped (e.g. "browser data cleared").
 */

const databases = new Map(); // name -> { stores: Map(storeName -> {keyPath, autoIncrement, nextKey, data: Map}) }

function makeRequest() {
  const request = {};
  request.onsuccess = null;
  request.onerror = null;
  return request;
}

function resolveRequestSuccess(request, result) {
  queueMicrotask(() => {
    request.result = result;
    if (request.onsuccess) request.onsuccess({ target: request });
  });
}

function resolveRequestError(request, error) {
  queueMicrotask(() => {
    request.error = error;
    if (request.onerror) request.onerror({ target: request });
  });
}

function makeStoreHandle(storeRecord) {
  return {
    add(value) {
      const request = makeRequest();
      let key = value[storeRecord.keyPath];
      if (storeRecord.autoIncrement && key === undefined) {
        key = storeRecord.nextKey++;
        value = { ...value, [storeRecord.keyPath]: key };
      }
      if (storeRecord.data.has(key)) {
        resolveRequestError(request, new Error("Key already exists"));
      } else {
        storeRecord.data.set(key, value);
        resolveRequestSuccess(request, key);
      }
      return request;
    },
    put(value) {
      const request = makeRequest();
      const key = value[storeRecord.keyPath];
      storeRecord.data.set(key, value);
      resolveRequestSuccess(request, key);
      return request;
    },
    get(key) {
      const request = makeRequest();
      resolveRequestSuccess(request, storeRecord.data.get(key));
      return request;
    },
    getAll() {
      const request = makeRequest();
      resolveRequestSuccess(request, Array.from(storeRecord.data.values()));
      return request;
    },
    delete(key) {
      const request = makeRequest();
      storeRecord.data.delete(key);
      resolveRequestSuccess(request, undefined);
      return request;
    },
    clear() {
      const request = makeRequest();
      storeRecord.data.clear();
      resolveRequestSuccess(request, undefined);
      return request;
    },
  };
}

function makeDbHandle(dbEntry) {
  return {
    objectStoreNames: {
      contains: (name) => dbEntry.stores.has(name),
    },
    createObjectStore(name, { keyPath, autoIncrement = false } = {}) {
      dbEntry.stores.set(name, { keyPath, autoIncrement, nextKey: 1, data: new Map() });
      return makeStoreHandle(dbEntry.stores.get(name));
    },
    transaction(storeNames, mode) {
      const names = Array.isArray(storeNames) ? storeNames : [storeNames];
      return {
        objectStore(name) {
          if (!names.includes(name)) throw new Error(`Store ${name} not in transaction scope`);
          return makeStoreHandle(dbEntry.stores.get(name));
        },
      };
    },
  };
}

function fakeIndexedDBOpen(name, version) {
  const request = makeRequest();
  let dbEntry = databases.get(name);
  const isNew = !dbEntry;
  if (isNew) {
    dbEntry = { version, stores: new Map() };
    databases.set(name, dbEntry);
  }
  const dbHandle = makeDbHandle(dbEntry);
  request.result = dbHandle;
  queueMicrotask(() => {
    if (isNew && request.onupgradeneeded) {
      request.onupgradeneeded({ target: request });
    }
    if (request.onsuccess) request.onsuccess({ target: request });
  });
  return request;
}

function installFakeIndexedDB() {
  global.indexedDB = { open: fakeIndexedDBOpen };
}

/** Simulates "browser data cleared" - all databases wiped. */
function resetFakeIndexedDB() {
  databases.clear();
}

module.exports = { installFakeIndexedDB, resetFakeIndexedDB };
