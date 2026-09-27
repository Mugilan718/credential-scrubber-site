/**
 * A minimal fake of the small subset of the File System Access API's
 * FileSystemDirectoryHandle/FileSystemFileHandle shape that
 * collectFilesFromDirectoryHandle() actually uses. Not a dependency -
 * local test infrastructure, so that pure directory-walking logic can be
 * exercised under plain Node, which has no File System Access API at all
 * (it's browser-only, currently Chromium-based browsers only).
 *
 * This does NOT simulate the real API's permission model
 * (queryPermission/requestPermission) or the actual folder-picker UI
 * (showDirectoryPicker()) - those can only be exercised in a real
 * browser. It covers exactly the read-a-tree-of-files shape
 * collectFilesFromDirectoryHandle() consumes.
 *
 * Build a tree with buildFakeDirectory(tree), where `tree` is a plain
 * nested object, e.g.:
 *   buildFakeDirectory({
 *     "config.json": '{"password": "fake123"}',
 *     "src": { "app.py": "password = 'fake456'" },
 *   })
 */

function makeFileHandle(name, content) {
  return {
    kind: "file",
    name,
    async getFile() {
      return {
        size: Buffer.byteLength(content, "utf8"),
        async text() {
          return content;
        },
      };
    },
  };
}

function makeDirectoryHandle(name, tree) {
  const entries = Object.entries(tree).map(([childName, value]) => {
    if (typeof value === "string") {
      return makeFileHandle(childName, value);
    }
    return makeDirectoryHandle(childName, value);
  });
  return {
    kind: "directory",
    name,
    async *values() {
      for (const entry of entries) yield entry;
    },
  };
}

function buildFakeDirectory(tree, name = "root") {
  return makeDirectoryHandle(name, tree);
}

module.exports = { buildFakeDirectory };
