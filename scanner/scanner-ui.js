(function () {
  const dropZone = document.getElementById("dropZone");
  const folderInput = document.getElementById("folderInput");
  const chooseBtn = document.getElementById("chooseBtn");
  const scanningState = document.getElementById("scanningState");
  const scanningText = document.getElementById("scanningText");
  const resultsState = document.getElementById("resultsState");
  const filesScannedCount = document.getElementById("filesScannedCount");
  const redactionCount = document.getElementById("redactionCount");
  const resultsTable = document.getElementById("resultsTable");
  const generateBtn = document.getElementById("generateBtn");
  const downloadGeneratedBtn = document.getElementById("downloadGeneratedBtn");
  const staleZipNote = document.getElementById("staleZipNote");
  const scanAgainBtn = document.getElementById("scanAgainBtn");
  const scanAgainSourceNote = document.getElementById("scanAgainSourceNote");
  const startOverBtn = document.getElementById("startOverBtn");
  const placeholderModeToggle = document.getElementById("placeholderModeToggle");
  const scanHistoryPanel = document.getElementById("scanHistoryPanel");
  const scanHistoryList = document.getElementById("scanHistoryList");
  const clearHistoryBtn = document.getElementById("clearHistoryBtn");
  const ruleEditorPanel = document.getElementById("ruleEditorPanel");
  const resetRulesBtn = document.getElementById("resetRulesBtn");
  const newKeyPatternInput = document.getElementById("newKeyPatternInput");
  const addKeyPatternBtn = document.getElementById("addKeyPatternBtn");
  const keyPatternError = document.getElementById("keyPatternError");
  const keyPatternList = document.getElementById("keyPatternList");
  const newAllowlistInput = document.getElementById("newAllowlistInput");
  const addAllowlistBtn = document.getElementById("addAllowlistBtn");
  const allowlistList = document.getElementById("allowlistList");
  const fsAccessArea = document.getElementById("fsAccessArea");
  const pickRememberedFolderBtn = document.getElementById("pickRememberedFolderBtn");
  const rememberedFolderArea = document.getElementById("rememberedFolderArea");
  const scanRememberedFolderBtn = document.getElementById("scanRememberedFolderBtn");
  const rememberedFolderName = document.getElementById("rememberedFolderName");
  const forgetFolderBtn = document.getElementById("forgetFolderBtn");
  const folderTreeState = document.getElementById("folderTreeState");
  const folderTreeSummary = document.getElementById("folderTreeSummary");
  const folderTreeList = document.getElementById("folderTreeList");
  const selectAllBtn = document.getElementById("selectAllBtn");
  const deselectAllBtn = document.getElementById("deselectAllBtn");
  const scanSelectedBtn = document.getElementById("scanSelectedBtn");
  const cancelTreeBtn = document.getElementById("cancelTreeBtn");
  const folderFilterPromptState = document.getElementById("folderFilterPromptState");
  const useLastSelectionBtn = document.getElementById("useLastSelectionBtn");
  const useFreshSelectionBtn = document.getElementById("useFreshSelectionBtn");
  const ignoreConfirmModal = document.getElementById("ignoreConfirmModal");
  const confirmIgnoreBtn = document.getElementById("confirmIgnoreBtn");
  const cancelIgnoreBtn = document.getElementById("cancelIgnoreBtn");
  const ignoredFindingsList = document.getElementById("ignoredFindingsList");

  // File System Access API (Phase 5) - Chromium-based browsers only today
  // (not Firefox/Safari). Feature-detected, never assumed - everything
  // below is additive on top of the existing drag-and-drop/"Choose folder"
  // flow, which behaves identically regardless of this support and needs
  // no change or error path when it's absent.
  const fsAccessSupported = typeof window.showDirectoryPicker === "function";

  let lastSanitizedFiles = [];
  let lastReportEntries = [];
  let lastFilesScanned = 0;

  // How the CURRENT results' files were obtained, for "Scan again"
  // (below): "handle" means a FileSystemDirectoryHandle (remembered
  // folder, Phase 5) that can be re-read from disk on demand; "memory"
  // means plain drag-and-drop/file-input File objects already read once,
  // with no way to silently re-read them - see scanAgainBtn's handler and
  // updateScanAgainSourceNote() for how this honesty distinction is
  // surfaced to the user rather than silently glossed over.
  let lastScanSource = null;
  let lastScanHandle = null;
  // One-time fallback message (e.g. a lapsed permission on the remembered
  // handle) that should be shown by the NEXT updateScanAgainSourceNote()
  // call and then cleared, rather than staying stuck on screen forever.
  let scanAgainFallbackWarning = null;

  // The most recently generated sanitized zip (generate/download
  // restructuring - ignore-safety checkpoint 2). Nothing is downloadable
  // until "Generate sanitized file" is clicked; any change to the reviewed
  // state afterward (an ignore, a restore, or a re-scan) invalidates it -
  // see invalidateGeneratedZip()/resetGeneratedZipState() below.
  let generatedZipBlob = null;
  let generatedZipUrl = null;
  let zipEverGenerated = false;
  let zipStale = false;

  // Ignored-findings review list (revertible ignores) - scoped to the
  // CURRENT scan's results, not the whole browser session: reset whenever
  // a new scan starts (scanReadableFiles()/startOverBtn below), since
  // findings ignored while looking at a different folder aren't relevant
  // once you've moved on. Each entry is the full report entry (file, line,
  // rule, key, before, after, occurrenceIndex) as returned by applyIgnores()'s
  // `restoredEntries` - everything reapplyRedaction() needs to reverse it,
  // and everything the list needs to display it. The underlying IndexedDB
  // ignore record (hash-based, used by future re-scans) is separate and
  // persists regardless - this list is just this tab's view onto "what did
  // I just ignore," not a replacement for that.
  let ignoredEntries = [];
  // Which result-row's ignore is awaiting confirmation in the modal.
  let pendingIgnoreIndex = null;
  let pendingIgnoreBtn = null;

  // Folder-filter tree (scan-scope selection) state. checkedPaths is the
  // single source of truth for what's included - see scanner-engine.js's
  // getNodeCheckState()/setNodeChecked() module comment. expandedFolders
  // is purely a UI concern (which folders have been clicked open) and
  // only affects what's currently rendered, never what's checked.
  let currentTree = null;
  let treeIndex = null;
  let checkedPaths = new Set();
  let expandedFolders = new Set();
  let pendingReadable = [];
  let pendingRawFilesForZip = [];
  // All paths seen this time round (before any filtering choice) and the
  // saved filter record (if any) a saved-selection prompt is currently
  // deciding between - both cleared once the user picks "use last"/"start
  // fresh" or cancels. See ScannerStorage.saveFolderFilter/getFolderFilter
  // and scanner-engine.js's reapplySavedSelection().
  let pendingAllPaths = [];
  let pendingSavedFilter = null;

  // This browser's local rule overrides (Phase 4) - loaded once at
  // startup, kept in memory, and persisted back to IndexedDB after every
  // edit. Always layered ON TOP of the shared base rules at scan time
  // (scanFiles()'s `ruleOverrides` option) - never written into
  // rules-data.js/window.RULES, which stay exactly as synced from the
  // Python project regardless of what's edited here.
  let currentOverrides = { keyPatternsAdded: [], keyPatternsRemoved: [], placeholderAllowlistAdded: [], placeholderAllowlistRemoved: [] };

  // Local-only persistence (scan history, ignore list) - IndexedDB is
  // near-universal in modern browsers, but this degrades gracefully rather
  // than breaking the scanner itself if it's ever unavailable (privacy
  // mode in some browsers restricts it, very old browsers lack it, etc).
  const storageSupported = typeof indexedDB !== "undefined" && typeof ScannerStorage !== "undefined";
  const dbPromise = storageSupported
    ? ScannerStorage.openScannerDB().catch(() => null)
    : Promise.resolve(null);

  if (!storageSupported) {
    if (scanHistoryPanel) scanHistoryPanel.classList.add("hidden");
    if (ruleEditorPanel) ruleEditorPanel.classList.add("hidden");
  }

  async function getDb() {
    return dbPromise;
  }

  const MAX_FILE_BYTES = 2 * 1024 * 1024; // skip anything absurdly large (likely binary/media)
  const BINARY_EXT = [".png",".jpg",".jpeg",".gif",".ico",".pdf",".zip",".exe",".dll",".so",".woff",".woff2",".ttf",".mp4",".mp3",".mov",".bin"];

  function isBinaryByName(name) {
    const lower = name.toLowerCase();
    return BINARY_EXT.some((ext) => lower.endsWith(ext));
  }

  // Icon + severity color per detection rule, for the results table.
  // "severity" here is a rough visual grouping to scan the table at a
  // glance, not a claim from the engine itself (scanner-engine.js never
  // ranks findings) - a private key or a credential embedded in a URL get
  // the strongest (danger) treatment since the secret is either maximally
  // powerful or already partway toward being exposed (e.g. in a URL a
  // browser/proxy might log); everything else is a normal finding, split
  // only by shape (key-name match / token-shaped / network-shaped /
  // generic-entropy) for visual variety, not because one is "worse."
  const RULE_DISPLAY = {
    key_name_match: { icon: "key", sev: "sev-cyan" },
    aws_access_key_id: { icon: "hash", sev: "sev-violet" },
    aws_secret_key_assignment: { icon: "hash", sev: "sev-violet" },
    github_token: { icon: "hash", sev: "sev-violet" },
    slack_token: { icon: "hash", sev: "sev-violet" },
    jwt_token: { icon: "hash", sev: "sev-violet" },
    bearer_token: { icon: "hash", sev: "sev-violet" },
    private_key_block: { icon: "key", sev: "sev-danger" },
    url_with_credentials: { icon: "link", sev: "sev-danger" },
    ipv4_address: { icon: "link", sev: "sev-cyan" },
    ipv6_address: { icon: "link", sev: "sev-cyan" },
    generic_url: { icon: "link", sev: "sev-cyan" },
    email_address: { icon: "hash", sev: "sev-cyan" },
    high_entropy: { icon: "alert", sev: "sev-violet" },
  };
  const DEFAULT_RULE_DISPLAY = { icon: "hash", sev: "sev-cyan" };

  function ruleDisplayFor(rule) {
    const base = rule.startsWith("multiline_concat_") ? rule.slice("multiline_concat_".length) : rule;
    return RULE_DISPLAY[base] || DEFAULT_RULE_DISPLAY;
  }

  chooseBtn.addEventListener("click", () => folderInput.click());
  dropZone.addEventListener("click", (e) => {
    if (e.target === chooseBtn) return;
    // Don't hijack a click on the placeholder-mode toggle, or any of the
    // Phase 5 remembered-folder controls, into opening the folder picker -
    // only the empty drop area and its instructional text should do that.
    if (e.target.closest(".placeholder-toggle")) return;
    if (e.target.closest(".remembered-folder-area")) return;
    if (e.target.closest(".fs-access-area")) return;
    folderInput.click();
  });

  folderInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files.length) handleFileList(e.target.files);
  });

  ["dragenter", "dragover"].forEach((evt) =>
    dropZone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropZone.classList.add("drag-over");
    })
  );
  ["dragleave", "drop"].forEach((evt) =>
    dropZone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropZone.classList.remove("drag-over");
    })
  );

  dropZone.addEventListener("drop", async (e) => {
    const items = e.dataTransfer.items;
    if (!items || !items.length) return;
    const files = await readDataTransferItems(items);
    if (files.length) handleFileList(files);
  });

  // Recursively walk dropped directory entries (drag-and-drop uses a different
  // API than the file input's webkitdirectory attribute).
  async function readDataTransferItems(items) {
    const entries = [];
    for (const item of items) {
      const entry = item.webkitGetAsEntry ? item.webkitGetAsEntry() : null;
      if (entry) entries.push(entry);
    }
    const files = [];
    async function walk(entry, path) {
      if (entry.isFile) {
        const file = await new Promise((res, rej) => entry.file(res, rej));
        file.relativePath = path + entry.name;
        files.push(file);
      } else if (entry.isDirectory) {
        const reader = entry.createReader();
        const children = await new Promise((res, rej) => reader.readEntries(res, rej));
        for (const child of children) {
          await walk(child, path + entry.name + "/");
        }
      }
    }
    for (const entry of entries) await walk(entry, "");
    return files;
  }

  async function handleFileList(fileList) {
    lastScanSource = "memory";
    lastScanHandle = null;
    dropZone.classList.add("hidden");
    scanningState.classList.remove("hidden");
    resultsState.classList.add("hidden");
    if (folderTreeState) folderTreeState.classList.add("hidden");
    if (folderFilterPromptState) folderFilterPromptState.classList.add("hidden");

    const files = Array.from(fileList);
    scanningText.textContent = `Reading ${files.length} files…`;

    const readable = [];
    const rawFilesForZip = [];

    for (const file of files) {
      const relPath = file.relativePath || file.webkitRelativePath || file.name;
      if (isBinaryByName(relPath) || file.size > MAX_FILE_BYTES) {
        // Carried through to the zip untouched, so the downloaded copy is
        // a complete mirror of the original folder.
        rawFilesForZip.push({ path: relPath, content: file, binary: true, rawFile: true });
        continue;
      }
      try {
        const content = await readFileAsText(file);
        readable.push({ path: relPath, content });
      } catch (e) {
        // Unreadable - skip silently, same as an oversized/binary file.
      }
    }

    await presentFolderTree(readable, rawFilesForZip);
  }

  /**
   * Shows the folder-filter tree. Everything is checked by default UNLESS
   * a saved filter selection exists from a previous scan of an overlapping
   * set of paths (checkpoint 2) - in that case the user is asked first via
   * the "use last selection / start fresh" prompt, and the tree is only
   * shown (with the saved or fresh selection applied) once they answer.
   * Does NOT scan yet - scanning happens only once the user confirms via
   * "Scan selected files".
   */
  async function presentFolderTree(readable, rawFilesForZip) {
    // scanFiles() silently drops any path under a SKIP_DIRS segment
    // (.git, node_modules, etc.) regardless of what's checked - filtering
    // them out of the tree too keeps "N of M files selected" honest and
    // avoids offering a checkbox for content that could never end up in
    // the output either way.
    const notSkipped = (f) => !f.path.split("/").some((seg) => SKIP_DIRS.has(seg));
    pendingReadable = readable.filter(notSkipped);
    pendingRawFilesForZip = rawFilesForZip.filter(notSkipped);

    const allPaths = pendingReadable.map((f) => f.path).concat(pendingRawFilesForZip.map((f) => f.path));
    pendingAllPaths = allPaths;
    currentTree = buildFileTree(allPaths);
    treeIndex = indexFileTree(currentTree);
    checkedPaths = new Set(allPaths); // everything included by default, until a saved filter says otherwise
    expandedFolders = new Set(); // top-level only, expand on demand - see renderTree()

    scanningState.classList.add("hidden");
    resultsState.classList.add("hidden");
    dropZone.classList.add("hidden");

    if (!folderTreeState) {
      // No tree UI available for some reason - fall back to scanning
      // everything, rather than leaving the user stuck on a blank page.
      await scanReadableFiles(pendingReadable, pendingRawFilesForZip);
      return;
    }

    const db = await getDb();
    const savedFilter = db ? await ScannerStorage.getFolderFilter(db) : null;
    if (savedFilter && folderFilterPromptState) {
      pendingSavedFilter = savedFilter;
      folderFilterPromptState.classList.remove("hidden");
      return; // wait for the user to choose "use last" or "start fresh"
    }

    folderTreeState.classList.remove("hidden");
    renderTree();
  }

  if (useLastSelectionBtn) {
    useLastSelectionBtn.addEventListener("click", () => {
      if (pendingSavedFilter) {
        checkedPaths = reapplySavedSelection(pendingAllPaths, pendingSavedFilter.allPaths, pendingSavedFilter.checkedPaths);
      }
      pendingSavedFilter = null;
      if (folderFilterPromptState) folderFilterPromptState.classList.add("hidden");
      if (folderTreeState) {
        folderTreeState.classList.remove("hidden");
        renderTree();
      }
    });
  }

  if (useFreshSelectionBtn) {
    useFreshSelectionBtn.addEventListener("click", () => {
      checkedPaths = new Set(pendingAllPaths); // everything checked
      pendingSavedFilter = null;
      if (folderFilterPromptState) folderFilterPromptState.classList.add("hidden");
      if (folderTreeState) {
        folderTreeState.classList.remove("hidden");
        renderTree();
      }
    });
  }

  /**
   * Renders only the currently-expanded portion of the tree (top-level
   * children always shown; a folder's own children are only rendered
   * once it's been expanded at least once) - keeps this fast even for a
   * project with thousands of files, since DOM node count is bounded by
   * what the user has actually clicked open, not the project's total size.
   */
  function renderTree() {
    if (!folderTreeList || !currentTree) return;
    let html = "";
    for (const child of currentTree.children) {
      html += treeRowHtml(child, 0);
    }
    folderTreeList.innerHTML = html || `<p class="scan-history-empty">No files found.</p>`;
    folderTreeList.querySelectorAll('[data-indeterminate="true"]').forEach((cb) => {
      cb.indeterminate = true;
    });
    updateTreeSummary();
  }

  function treeRowHtml(node, depth) {
    const state = getNodeCheckState(node, checkedPaths);
    const indent = `padding-left:${depth * 20 + 12}px`;
    if (node.type === "file") {
      return `<div class="tree-row tree-file" style="${indent}">
        <span class="tree-toggle-spacer"></span>
        <input type="checkbox" class="tree-checkbox" data-path="${escapeHtml(node.path)}" ${state === "checked" ? "checked" : ""} />
        <svg class="icon tree-icon"><use href="#icon-file"/></svg>
        <span class="tree-name" title="${escapeHtml(node.name)}">${escapeHtml(node.name)}</span>
      </div>`;
    }
    const expanded = expandedFolders.has(node.path);
    const fileCount = collectFilePaths(node).length;
    let html = `<div class="tree-row tree-folder" style="${indent}">
      <button type="button" class="tree-toggle" data-path="${escapeHtml(node.path)}" aria-expanded="${expanded}" aria-label="${expanded ? "Collapse" : "Expand"} ${escapeHtml(node.name)}">
        <svg class="icon"><use href="#icon-chevron"/></svg>
      </button>
      <input type="checkbox" class="tree-checkbox" data-path="${escapeHtml(node.path)}" ${state === "checked" ? "checked" : ""} ${state === "indeterminate" ? 'data-indeterminate="true"' : ""} />
      <svg class="icon tree-icon"><use href="#icon-folder"/></svg>
      <span class="tree-name" title="${escapeHtml(node.name)}">${escapeHtml(node.name)}</span>
      <span class="tree-count">${fileCount} file${fileCount === 1 ? "" : "s"}</span>
    </div>`;
    if (expanded) {
      for (const child of node.children) {
        html += treeRowHtml(child, depth + 1);
      }
    }
    return html;
  }

  function updateTreeSummary() {
    if (!currentTree) return;
    const total = collectFilePaths(currentTree).length;
    const checkedCount = checkedPaths.size;
    if (folderTreeSummary) folderTreeSummary.textContent = `${checkedCount} of ${total} files selected`;
    if (scanSelectedBtn) {
      scanSelectedBtn.textContent = `Scan selected files (${checkedCount})`;
      scanSelectedBtn.disabled = checkedCount === 0;
    }
  }

  if (folderTreeList) {
    folderTreeList.addEventListener("click", (e) => {
      const toggleBtn = e.target.closest(".tree-toggle");
      if (!toggleBtn) return;
      const path = toggleBtn.dataset.path;
      if (expandedFolders.has(path)) expandedFolders.delete(path);
      else expandedFolders.add(path);
      renderTree();
    });

    folderTreeList.addEventListener("change", (e) => {
      const checkbox = e.target.closest(".tree-checkbox");
      if (!checkbox) return;
      const node = treeIndex.get(checkbox.dataset.path);
      if (!node) return;
      checkedPaths = setNodeChecked(node, checkbox.checked, checkedPaths);
      renderTree();
    });
  }

  if (selectAllBtn) {
    selectAllBtn.addEventListener("click", () => {
      if (!currentTree) return;
      checkedPaths = setNodeChecked(currentTree, true, checkedPaths);
      renderTree();
    });
  }

  if (deselectAllBtn) {
    deselectAllBtn.addEventListener("click", () => {
      if (!currentTree) return;
      checkedPaths = setNodeChecked(currentTree, false, checkedPaths);
      renderTree();
    });
  }

  if (scanSelectedBtn) {
    scanSelectedBtn.addEventListener("click", async () => {
      if (folderTreeState) folderTreeState.classList.add("hidden");
      scanningState.classList.remove("hidden");
      scanningText.textContent = "Scanning selected files…";

      // Remember this selection for next time - same local-only storage
      // approach as scan history/ignores (see storage.js's module comment).
      const db = await getDb();
      if (db) await ScannerStorage.saveFolderFilter(db, pendingAllPaths, Array.from(checkedPaths));

      const filteredReadable = filterFilesByCheckedPaths(pendingReadable, checkedPaths);
      const filteredRaw = filterFilesByCheckedPaths(pendingRawFilesForZip, checkedPaths);
      await scanReadableFiles(filteredReadable, filteredRaw);
    });
  }

  if (cancelTreeBtn) {
    cancelTreeBtn.addEventListener("click", () => {
      if (folderTreeState) folderTreeState.classList.add("hidden");
      if (folderFilterPromptState) folderFilterPromptState.classList.add("hidden");
      dropZone.classList.remove("hidden");
      pendingReadable = [];
      pendingRawFilesForZip = [];
      pendingAllPaths = [];
      pendingSavedFilter = null;
      currentTree = null;
    });
  }

  /**
   * Shared downstream pipeline: takes already-read {path, content} files
   * (from the classic file-input/drag-drop flow OR Phase 5's remembered-
   * folder flow) through detection, ignore-reconciliation, rendering, and
   * scan-history persistence. `rawFilesForZip` carries through any
   * skipped binary/oversized files untouched, same as before.
   */
  async function scanReadableFiles(readable, rawFilesForZip, { isRescan = false } = {}) {
    // A re-scan ("Scan again") only invalidates whatever was already
    // generated for download (see Phase B) - a brand-new scan of a freshly
    // chosen folder has no such prior result to speak of, so it gets a
    // full, clean reset instead (no "stale" messaging that would imply
    // something existed a moment ago).
    if (isRescan) {
      invalidateGeneratedZip();
    } else {
      resetGeneratedZipState();
    }

    if (!isRescan) {
      scanningText.textContent = `Scanning ${readable.length} files…`;
    }
    // Yield to the browser so the "scanning" state actually paints before the
    // (synchronous, potentially CPU-heavy) scan runs.
    await new Promise((r) => setTimeout(r, 30));

    const placeholderMode = !!(placeholderModeToggle && placeholderModeToggle.checked);
    let scanResult = scanFiles(readable, { placeholderMode, ruleOverrides: currentOverrides });

    // Reconcile against any findings the user previously ignored (see
    // storage.js's module comment): a finding whose value hasn't changed
    // since it was ignored is suppressed and its original text restored;
    // one whose value HAS changed reappears, flagged, rather than staying
    // silently hidden.
    const db = await getDb();
    if (db) {
      const ignoreMap = await ScannerStorage.getIgnoreMap(db);
      scanResult = await applyIgnores(scanResult, ignoreMap);
    }

    lastSanitizedFiles = scanResult.sanitizedFiles.concat(rawFilesForZip || []);
    lastReportEntries = scanResult.reportEntries;
    lastFilesScanned = readable.length;
    // Reflects everything actually suppressed/restored in THIS pass -
    // whether ignored earlier this session or persisted from a previous
    // one - rather than being wiped on every scan regardless of whether
    // those findings are still (correctly) hidden underneath. This also
    // makes "Scan again" behave sensibly: a finding ignored before
    // re-scanning stays visible in "Ignored findings," restorable, instead
    // of vanishing from the list while remaining silently suppressed.
    ignoredEntries = scanResult.restoredEntries || [];
    renderIgnoredFindings();

    renderResults(lastFilesScanned, lastReportEntries);
    updateScanAgainSourceNote();

    // Scan history stores only the SAFE report - file/line/rule/key - and
    // explicitly never the raw "before"/"after" values, even though those
    // are already in memory for this session (see the panel's own
    // local-only disclaimer in scanner/index.html).
    if (db) {
      const safeEntries = lastReportEntries.map((e) => ({ file: e.file, line: e.line, rule: e.rule, key: e.key }));
      await ScannerStorage.saveScanHistoryEntry(db, {
        fileCount: lastFilesScanned,
        findingCount: lastReportEntries.length,
        entries: safeEntries,
      });
      await refreshScanHistoryUI();
    }
  }

  /** Reflects generatedZipUrl/zipStale/zipEverGenerated onto the Generate/Download UI. */
  function updateGenerateDownloadUI() {
    if (generateBtn) {
      generateBtn.textContent = zipEverGenerated ? "Regenerate sanitized file" : "Generate sanitized file";
    }
    if (downloadGeneratedBtn) {
      if (generatedZipUrl && !zipStale) {
        downloadGeneratedBtn.classList.remove("hidden");
      } else {
        downloadGeneratedBtn.classList.add("hidden");
      }
    }
    if (staleZipNote) {
      if (zipStale) {
        staleZipNote.textContent = 'Your changes since the last generated file (an ignore, a restore, or a re-scan) mean it\'s now out of date — click "Generate sanitized file" again before downloading.';
        staleZipNote.classList.remove("hidden");
      } else {
        staleZipNote.classList.add("hidden");
      }
    }
  }

  /** Marks the current generated zip (if any) stale - an ignore/restore/re-scan happened since. */
  function invalidateGeneratedZip() {
    if (generatedZipUrl) URL.revokeObjectURL(generatedZipUrl);
    generatedZipUrl = null;
    generatedZipBlob = null;
    if (zipEverGenerated) zipStale = true;
    updateGenerateDownloadUI();
  }

  /** Full reset for a brand-new scan (not a re-scan of the same results) - back to "not yet generated." */
  function resetGeneratedZipState() {
    if (generatedZipUrl) URL.revokeObjectURL(generatedZipUrl);
    generatedZipUrl = null;
    generatedZipBlob = null;
    zipEverGenerated = false;
    zipStale = false;
    updateGenerateDownloadUI();
  }

  /**
   * Surfaces the honesty distinction from "Scan again"'s doc comment: a
   * memory-sourced scan can never silently reflect on-disk edits, so this
   * stays visible the whole time such results are shown, not just right
   * after clicking. A one-time fallback warning (lapsed handle permission)
   * takes priority and is cleared after being shown once.
   */
  function updateScanAgainSourceNote() {
    if (!scanAgainSourceNote) return;
    if (scanAgainFallbackWarning) {
      scanAgainSourceNote.textContent = scanAgainFallbackWarning;
      scanAgainSourceNote.classList.remove("hidden");
      scanAgainFallbackWarning = null;
      return;
    }
    if (lastScanSource === "memory") {
      scanAgainSourceNote.textContent = 'Re-scanning the same files already loaded — edits made since dropping this folder won\'t be reflected. Use "Choose different folder" to pick it again fresh.';
      scanAgainSourceNote.classList.remove("hidden");
    } else {
      scanAgainSourceNote.classList.add("hidden");
    }
  }

  function readFileAsText(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = reject;
      reader.readAsText(file);
    });
  }

  function renderResults(filesScanned, entries) {
    scanningState.classList.add("hidden");
    resultsState.classList.remove("hidden");

    filesScannedCount.textContent = filesScanned;
    redactionCount.textContent = entries.length;

    if (entries.length === 0) {
      resultsTable.innerHTML = `<div class="results-empty">No hardcoded credentials found in this scan.</div>`;
      return;
    }

    let html = "";
    entries.forEach((e, i) => {
      const changedBadge = e.previously_ignored_value_changed
        ? `<span class="result-changed-badge" title="This was previously ignored, but the value has since changed - it's shown again rather than staying hidden.">⚠ changed since ignored</span>`
        : "";
      const display = ruleDisplayFor(e.rule);
      html += `<div class="result-row">
        <div class="result-line">${e.line}</div>
        <div class="result-file" title="${escapeHtml(e.file)}">${escapeHtml(e.file)}</div>
        <div class="result-rule">
          <span class="result-rule-badge ${display.sev}"><svg class="icon"><use href="#icon-${display.icon}"/></svg></span>
          <span class="result-rule-text">${escapeHtml(e.rule)}</span>
          ${changedBadge}
        </div>
        <div class="result-key">${escapeHtml(e.key || "—")}</div>
        <div class="result-action">
          ${storageSupported ? `<button class="ignore-btn" data-index="${i}" title="Remember this exact value as a known false positive/accepted risk on this device only"><svg class="icon"><use href="#icon-x"/></svg> Ignore</button>` : ""}
        </div>
      </div>`;
    });
    resultsTable.innerHTML = html;
  }

  // Clicking "Ignore" only asks for confirmation - it does NOT itself
  // restore anything yet. The actual ignore (which un-redacts the real
  // value into the working copy) only happens once the user explicitly
  // confirms in the modal below, so a single accidental click can never
  // silently unmask a real secret.
  resultsTable.addEventListener("click", (e) => {
    const btn = e.target.closest(".ignore-btn");
    if (!btn) return;
    pendingIgnoreIndex = Number(btn.dataset.index);
    pendingIgnoreBtn = btn;
    if (ignoreConfirmModal) ignoreConfirmModal.classList.remove("hidden");
  });

  if (cancelIgnoreBtn) {
    cancelIgnoreBtn.addEventListener("click", () => {
      pendingIgnoreIndex = null;
      pendingIgnoreBtn = null;
      if (ignoreConfirmModal) ignoreConfirmModal.classList.add("hidden");
    });
  }

  if (confirmIgnoreBtn) {
    confirmIgnoreBtn.addEventListener("click", async () => {
      const idx = pendingIgnoreIndex;
      const btn = pendingIgnoreBtn;
      pendingIgnoreIndex = null;
      pendingIgnoreBtn = null;
      if (ignoreConfirmModal) ignoreConfirmModal.classList.add("hidden");
      if (idx == null) return;
      await performIgnore(idx, btn);
    });
  }

  async function performIgnore(idx, btn) {
    const entry = lastReportEntries[idx];
    if (!entry) return;

    const db = await getDb();
    if (!db) return;

    if (btn) {
      btn.disabled = true;
      btn.textContent = "Ignoring…";
    }

    const hash = await hashValue(entry.before);
    await ScannerStorage.setIgnore(db, entry.file, entry.key, entry.rule, hash);

    // Reflect it immediately in this session's results and the
    // downloadable output, using the exact same reconciliation logic a
    // future re-scan would apply - not a separate, ad-hoc UI-only removal.
    const oneEntryIgnoreMap = { [ignoreKeyFor(entry.file, entry.key, entry.rule)]: hash };
    const reconciled = await applyIgnores(
      { sanitizedFiles: lastSanitizedFiles, reportEntries: lastReportEntries },
      oneEntryIgnoreMap
    );
    lastSanitizedFiles = reconciled.sanitizedFiles;
    lastReportEntries = reconciled.reportEntries;

    if (reconciled.restoredEntries && reconciled.restoredEntries.length) {
      ignoredEntries = ignoredEntries.concat(reconciled.restoredEntries);
      renderIgnoredFindings();
    }
    invalidateGeneratedZip();

    // Fade the row out before re-rendering without it, rather than an
    // instant cut - a no-op visually for prefers-reduced-motion (the
    // animation is disabled globally, so this timeout is the only delay,
    // matching what CSS would have taken anyway).
    const row = btn ? btn.closest(".result-row") : null;
    if (row) {
      row.classList.add("ignoring");
      await new Promise((r) => setTimeout(r, 220));
    }
    renderResults(lastFilesScanned, lastReportEntries);
  }

  /** Renders the "ignored findings (this scan)" review list. */
  function renderIgnoredFindings() {
    if (!ignoredFindingsList) return;
    if (ignoredEntries.length === 0) {
      ignoredFindingsList.innerHTML = `<p class="scan-history-empty">Nothing ignored yet.</p>`;
      return;
    }
    ignoredFindingsList.innerHTML = ignoredEntries.map((entry, i) => `
      <div class="scan-history-row">
        <span class="scan-history-left">
          <svg class="icon scan-history-row-icon"><use href="#icon-shield"/></svg>
          <span>
            <span class="scan-history-date">${escapeHtml(entry.key || "—")} <span class="ignored-finding-meta">${escapeHtml(entry.rule)}</span></span>
            <span class="ignored-finding-meta" title="${escapeHtml(entry.file)}">${escapeHtml(entry.file)}:${entry.line}</span>
          </span>
        </span>
        <button class="restore-btn" data-index="${i}" title="Re-mask this value, remove it from the local ignore list, and bring it back into the results above"><svg class="icon"><use href="#icon-undo"/></svg> Restore redaction</button>
      </div>
    `).join("");
  }

  if (ignoredFindingsList) {
    ignoredFindingsList.addEventListener("click", async (e) => {
      const btn = e.target.closest(".restore-btn");
      if (!btn) return;
      const idx = Number(btn.dataset.index);
      const entry = ignoredEntries[idx];
      if (!entry) return;

      btn.disabled = true;
      btn.textContent = "Restoring…";

      const db = await getDb();
      if (db) await ScannerStorage.removeIgnore(db, entry.file, entry.key, entry.rule);

      lastSanitizedFiles = reapplyRedaction(lastSanitizedFiles, entry);
      ignoredEntries = ignoredEntries.filter((_, i) => i !== idx);

      // Bring it back into the visible results, in the same relative order
      // (by file, then line) rather than just appending it at the end.
      const { occurrenceIndex, ...restoredEntry } = entry;
      lastReportEntries = lastReportEntries.concat([restoredEntry]).sort((a, b) => {
        if (a.file !== b.file) return a.file < b.file ? -1 : 1;
        return a.line - b.line;
      });
      invalidateGeneratedZip();

      renderIgnoredFindings();
      renderResults(lastFilesScanned, lastReportEntries);
    });
  }

  async function refreshScanHistoryUI() {
    if (!scanHistoryList) return;
    const db = await getDb();
    if (!db) return;
    const history = await ScannerStorage.listScanHistory(db);
    if (history.length === 0) {
      scanHistoryList.innerHTML = `<p class="scan-history-empty">No scans yet.</p>`;
      return;
    }
    scanHistoryList.innerHTML = history.map((h) => {
      const when = new Date(h.timestamp).toLocaleString();
      const findingWord = h.findingCount === 1 ? "finding" : "findings";
      return `<div class="scan-history-row">
        <span class="scan-history-left">
          <svg class="icon scan-history-row-icon"><use href="#icon-clock"/></svg>
          <span class="scan-history-date">${escapeHtml(when)}</span>
        </span>
        <span class="scan-history-counts">${h.fileCount} files scanned · ${h.findingCount} ${findingWord}</span>
      </div>`;
    }).join("");
  }

  if (clearHistoryBtn) {
    clearHistoryBtn.addEventListener("click", async () => {
      const db = await getDb();
      if (!db) return;
      await ScannerStorage.clearScanHistory(db);
      await refreshScanHistoryUI();
    });
  }

  refreshScanHistoryUI();

  // -----------------------------------------------------------------------
  // Rule editor (Phase 4)
  // -----------------------------------------------------------------------

  function renderRuleEditor() {
    if (!keyPatternList || !allowlistList) return;
    const base = getBaseRuleSnapshot();

    let keyHtml = "";
    base.keyPatternSources.forEach((p) => {
      const disabled = currentOverrides.keyPatternsRemoved.includes(p);
      keyHtml += `<div class="rule-editor-row${disabled ? " is-disabled" : ""}">
        <span class="rule-editor-text">${escapeHtml(p)}</span>
        <span class="rule-editor-tag">base</span>
        <button class="rule-editor-toggle" data-kind="base" data-pattern="${escapeHtml(p)}">${disabled ? "Enable" : "Disable"}</button>
      </div>`;
    });
    currentOverrides.keyPatternsAdded.forEach((p) => {
      keyHtml += `<div class="rule-editor-row">
        <span class="rule-editor-text">${escapeHtml(p)}</span>
        <span class="rule-editor-tag rule-editor-tag-custom">custom</span>
        <button class="rule-editor-toggle" data-kind="added" data-pattern="${escapeHtml(p)}">Remove</button>
      </div>`;
    });
    keyPatternList.innerHTML = keyHtml;

    let allowHtml = "";
    base.placeholderAllowlist.forEach((v) => {
      const disabled = currentOverrides.placeholderAllowlistRemoved.map((x) => x.toLowerCase()).includes(v.toLowerCase());
      allowHtml += `<div class="rule-editor-row${disabled ? " is-disabled" : ""}">
        <span class="rule-editor-text">${escapeHtml(v)}</span>
        <span class="rule-editor-tag">base</span>
        <button class="rule-editor-toggle" data-list="allowlist" data-kind="base" data-value="${escapeHtml(v)}">${disabled ? "Enable" : "Disable"}</button>
      </div>`;
    });
    currentOverrides.placeholderAllowlistAdded.forEach((v) => {
      allowHtml += `<div class="rule-editor-row">
        <span class="rule-editor-text">${escapeHtml(v)}</span>
        <span class="rule-editor-tag rule-editor-tag-custom">custom</span>
        <button class="rule-editor-toggle" data-list="allowlist" data-kind="added" data-value="${escapeHtml(v)}">Remove</button>
      </div>`;
    });
    allowlistList.innerHTML = allowHtml;
  }

  async function persistOverrides() {
    const db = await getDb();
    if (!db) return;
    await ScannerStorage.saveRuleOverrides(db, currentOverrides);
  }

  async function loadRuleOverrides() {
    const db = await getDb();
    if (!db) {
      renderRuleEditor();
      return;
    }
    currentOverrides = await ScannerStorage.getRuleOverrides(db);
    renderRuleEditor();
  }

  loadRuleOverrides();

  if (addKeyPatternBtn) {
    addKeyPatternBtn.addEventListener("click", async () => {
      const raw = newKeyPatternInput.value.trim();
      keyPatternError.textContent = "";
      if (!raw) return;
      try {
        // eslint-disable-next-line no-new
        new RegExp(raw, "gi"); // validate before accepting - never let an invalid pattern into the effective ruleset
      } catch (e) {
        keyPatternError.textContent = `Not a valid pattern: ${e.message}`;
        return;
      }
      const base = getBaseRuleSnapshot();
      if (base.keyPatternSources.includes(raw) || currentOverrides.keyPatternsAdded.includes(raw)) {
        keyPatternError.textContent = "That pattern already exists.";
        return;
      }
      currentOverrides.keyPatternsAdded.push(raw);
      newKeyPatternInput.value = "";
      await persistOverrides();
      renderRuleEditor();
    });
  }

  if (addAllowlistBtn) {
    addAllowlistBtn.addEventListener("click", async () => {
      const raw = newAllowlistInput.value.trim();
      if (!raw) return;
      currentOverrides.placeholderAllowlistAdded.push(raw);
      newAllowlistInput.value = "";
      await persistOverrides();
      renderRuleEditor();
    });
  }

  if (keyPatternList) {
    keyPatternList.addEventListener("click", async (e) => {
      const btn = e.target.closest(".rule-editor-toggle");
      if (!btn) return;
      const pattern = btn.dataset.pattern;
      if (btn.dataset.kind === "added") {
        currentOverrides.keyPatternsAdded = currentOverrides.keyPatternsAdded.filter((p) => p !== pattern);
      } else {
        const isCurrentlyRemoved = currentOverrides.keyPatternsRemoved.includes(pattern);
        currentOverrides.keyPatternsRemoved = isCurrentlyRemoved
          ? currentOverrides.keyPatternsRemoved.filter((p) => p !== pattern)
          : [...currentOverrides.keyPatternsRemoved, pattern];
      }
      await persistOverrides();
      renderRuleEditor();
    });
  }

  if (allowlistList) {
    allowlistList.addEventListener("click", async (e) => {
      const btn = e.target.closest(".rule-editor-toggle");
      if (!btn) return;
      const value = btn.dataset.value;
      if (btn.dataset.kind === "added") {
        currentOverrides.placeholderAllowlistAdded = currentOverrides.placeholderAllowlistAdded.filter((v) => v !== value);
      } else {
        const isCurrentlyRemoved = currentOverrides.placeholderAllowlistRemoved.map((v) => v.toLowerCase()).includes(value.toLowerCase());
        currentOverrides.placeholderAllowlistRemoved = isCurrentlyRemoved
          ? currentOverrides.placeholderAllowlistRemoved.filter((v) => v.toLowerCase() !== value.toLowerCase())
          : [...currentOverrides.placeholderAllowlistRemoved, value];
      }
      await persistOverrides();
      renderRuleEditor();
    });
  }

  if (resetRulesBtn) {
    resetRulesBtn.addEventListener("click", async () => {
      currentOverrides = { keyPatternsAdded: [], keyPatternsRemoved: [], placeholderAllowlistAdded: [], placeholderAllowlistRemoved: [] };
      const db = await getDb();
      if (db) await ScannerStorage.resetRuleOverrides(db);
      renderRuleEditor();
    });
  }

  // -----------------------------------------------------------------------
  // Remembered folder (Phase 5, File System Access API)
  // -----------------------------------------------------------------------

  let fsAccessError = null;

  function renderFsAccessArea(remembered) {
    if (!fsAccessArea || !rememberedFolderArea) return;
    if (remembered) {
      rememberedFolderArea.classList.remove("hidden");
      rememberedFolderName.textContent = remembered.name;
      fsAccessArea.classList.add("hidden");
    } else {
      rememberedFolderArea.classList.add("hidden");
      fsAccessArea.classList.remove("hidden");
    }
    let note = fsAccessArea.querySelector(".fs-access-error");
    if (fsAccessError) {
      if (!note) {
        note = document.createElement("p");
        note.className = "fs-access-error";
        fsAccessArea.appendChild(note);
      }
      note.textContent = fsAccessError;
    } else if (note) {
      note.remove();
    }
  }

  async function loadRememberedFolder() {
    if (!fsAccessSupported) {
      if (fsAccessArea) fsAccessArea.classList.add("hidden");
      if (rememberedFolderArea) rememberedFolderArea.classList.add("hidden");
      return;
    }
    const db = await getDb();
    const remembered = db ? await ScannerStorage.getFolderHandle(db) : null;
    renderFsAccessArea(remembered);
  }

  loadRememberedFolder();

  async function scanDirectoryHandle(handle) {
    lastScanSource = "handle";
    lastScanHandle = handle;
    dropZone.classList.add("hidden");
    scanningState.classList.remove("hidden");
    resultsState.classList.add("hidden");
    if (folderTreeState) folderTreeState.classList.add("hidden");
    if (folderFilterPromptState) folderFilterPromptState.classList.add("hidden");
    scanningText.textContent = "Reading remembered folder…";

    const { files: readable } = await collectFilesFromDirectoryHandle(handle, {
      maxFileBytes: MAX_FILE_BYTES,
      isBinaryByName,
    });
    await presentFolderTree(readable, []);
  }

  if (pickRememberedFolderBtn) {
    pickRememberedFolderBtn.addEventListener("click", async () => {
      fsAccessError = null;
      try {
        const handle = await window.showDirectoryPicker();
        const db = await getDb();
        if (db) await ScannerStorage.saveFolderHandle(db, handle, handle.name);
        renderFsAccessArea({ name: handle.name });
        await scanDirectoryHandle(handle);
      } catch (e) {
        // AbortError = the user closed the picker without choosing anything
        // - not an error worth showing.
        if (e && e.name !== "AbortError") {
          fsAccessError = "Couldn't access that folder. You can still use drag-and-drop or \"Choose folder\" above.";
          renderFsAccessArea(null);
        }
      }
    });
  }

  if (scanRememberedFolderBtn) {
    scanRememberedFolderBtn.addEventListener("click", async () => {
      const db = await getDb();
      const remembered = db ? await ScannerStorage.getFolderHandle(db) : null;
      if (!remembered) return;
      fsAccessError = null;
      try {
        // Permission is not guaranteed to persist across sessions - this
        // must be requested from within a user gesture (this click), which
        // is exactly where it's called from here.
        let permission = await remembered.handle.queryPermission({ mode: "read" });
        if (permission !== "granted") {
          permission = await remembered.handle.requestPermission({ mode: "read" });
        }
        if (permission !== "granted") {
          fsAccessError = "Access to this folder was not granted. Pick it again, or use drag-and-drop/\"Choose folder\" instead.";
          renderFsAccessArea(null);
          return;
        }
        await scanDirectoryHandle(remembered.handle);
      } catch (e) {
        fsAccessError = "Couldn't access the remembered folder (it may have been moved or deleted). Try remembering it again.";
        renderFsAccessArea(null);
      }
    });
  }

  if (forgetFolderBtn) {
    forgetFolderBtn.addEventListener("click", async () => {
      const db = await getDb();
      if (db) await ScannerStorage.clearFolderHandle(db);
      renderFsAccessArea(null);
    });
  }

  // "Generate sanitized file" locks in whatever's CURRENTLY ignored/
  // restored and builds the zip from it - nothing is downloadable before
  // this is clicked at least once (Phase B), and any change afterward
  // (an ignore, a restore, or a re-scan) invalidates this specific result
  // via invalidateGeneratedZip() rather than silently letting a stale zip
  // stay downloadable.
  if (generateBtn) {
    generateBtn.addEventListener("click", async () => {
      generateBtn.disabled = true;
      generateBtn.textContent = "Generating…";

      const zip = new JSZip();
      for (const f of lastSanitizedFiles) {
        zip.file(f.path, f.content); // rawFile entries carry a binary-safe File object directly
      }
      const blob = await zip.generateAsync({ type: "blob" });

      if (generatedZipUrl) URL.revokeObjectURL(generatedZipUrl);
      generatedZipBlob = blob;
      generatedZipUrl = URL.createObjectURL(blob);
      zipEverGenerated = true;
      zipStale = false;

      generateBtn.disabled = false;
      updateGenerateDownloadUI();
    });
  }

  if (downloadGeneratedBtn) {
    downloadGeneratedBtn.addEventListener("click", () => {
      if (!generatedZipUrl || zipStale) return; // shouldn't be reachable (hidden in that state), but never serve a stale/missing zip
      const a = document.createElement("a");
      a.href = generatedZipUrl;
      a.download = "sanitized-project.zip";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    });
  }

  // "Scan again" re-scans the SAME folder without reopening the filter
  // tree, preserving checkedPaths as-is (requirement: keep the current
  // filter selection). Behavior depends on how the folder was originally
  // provided - see lastScanSource's doc comment above.
  if (scanAgainBtn) {
    scanAgainBtn.addEventListener("click", async () => {
      resultsState.classList.add("hidden");
      scanningState.classList.remove("hidden");

      let usedFreshRead = false;
      if (lastScanSource === "handle" && lastScanHandle) {
        try {
          // Permission is not guaranteed to persist - must be requested
          // from within this click's user gesture, same as elsewhere in
          // the Phase 5 remembered-folder flow.
          let permission = await lastScanHandle.queryPermission({ mode: "read" });
          if (permission !== "granted") {
            permission = await lastScanHandle.requestPermission({ mode: "read" });
          }
          if (permission === "granted") {
            scanningText.textContent = "Re-reading folder from disk…";
            const { files: freshReadable } = await collectFilesFromDirectoryHandle(lastScanHandle, {
              maxFileBytes: MAX_FILE_BYTES,
              isBinaryByName,
            });
            const notSkipped = (f) => !f.path.split("/").some((seg) => SKIP_DIRS.has(seg));
            pendingReadable = freshReadable.filter(notSkipped);
            pendingRawFilesForZip = []; // handle-based reads never produce rawFilesForZip - see presentFolderTree()
            pendingAllPaths = pendingReadable.map((f) => f.path);
            currentTree = buildFileTree(pendingAllPaths);
            treeIndex = indexFileTree(currentTree);
            usedFreshRead = true;
          } else {
            scanAgainFallbackWarning = "Access to this folder was not granted, so this re-scan used the last loaded copy instead of reading fresh from disk.";
          }
        } catch (e) {
          // Falls through to the in-memory re-scan below rather than
          // leaving the user stuck - same graceful-degradation approach as
          // the rest of the File System Access API integration (Phase 5).
          scanAgainFallbackWarning = "Couldn't re-read this folder from disk (it may have moved or permission may have lapsed) - this re-scan used the last loaded copy instead.";
        }
      }

      if (!usedFreshRead) {
        scanningText.textContent = "Re-scanning already-loaded files…";
      }

      // checkedPaths is intentionally left untouched here - this is what
      // preserves the current folder-filter selection across "Scan again,"
      // rather than resetting to "everything checked."
      const filteredReadable = filterFilesByCheckedPaths(pendingReadable, checkedPaths);
      const filteredRaw = filterFilesByCheckedPaths(pendingRawFilesForZip, checkedPaths);
      await scanReadableFiles(filteredReadable, filteredRaw, { isRescan: true });
    });
  }

  startOverBtn.addEventListener("click", () => {
    folderInput.value = "";
    lastSanitizedFiles = [];
    lastReportEntries = [];
    lastFilesScanned = 0;
    pendingReadable = [];
    pendingRawFilesForZip = [];
    pendingAllPaths = [];
    pendingSavedFilter = null;
    currentTree = null;
    ignoredEntries = [];
    lastScanSource = null;
    lastScanHandle = null;
    scanAgainFallbackWarning = null;
    if (scanAgainSourceNote) scanAgainSourceNote.classList.add("hidden");
    resetGeneratedZipState();
    renderIgnoredFindings();
    resultsState.classList.add("hidden");
    dropZone.classList.remove("hidden");
  });

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  // Test-only hook: lets the Playwright screenshot checks in this
  // project drive the REAL presentFolderTree()/renderTree() closure
  // directly (e.g. with a synthetic file list), instead of a
  // hand-reconstructed copy of the markup - not used by the app itself,
  // and harmless to expose for a client-side, no-server tool like this.
  window.__scannerUiTestHooks = {
    presentFolderTree,
    getTreeState: () => ({ checkedPaths: new Set(checkedPaths), expandedFolders: new Set(expandedFolders) }),
    setExpanded: (path, expanded) => {
      if (expanded) expandedFolders.add(path);
      else expandedFolders.delete(path);
      renderTree();
    },
    isPromptVisible: () => !!(folderFilterPromptState && !folderFilterPromptState.classList.contains("hidden")),
    scanReadableFiles,
    isIgnoreConfirmVisible: () => !!(ignoreConfirmModal && !ignoreConfirmModal.classList.contains("hidden")),
    getIgnoredEntries: () => ignoredEntries.map((e) => ({ file: e.file, line: e.line, key: e.key, rule: e.rule })),
    getLastReportEntries: () => lastReportEntries.map((e) => ({ file: e.file, line: e.line, key: e.key, rule: e.rule })),
    getLastSanitizedFileContent: (path) => {
      const f = lastSanitizedFiles.find((f) => f.path === path);
      return f ? f.content : null;
    },
    getZipState: () => ({
      hasDownloadUrl: !!generatedZipUrl,
      isDownloadVisible: !!(downloadGeneratedBtn && !downloadGeneratedBtn.classList.contains("hidden")),
      zipStale: zipStale,
      isStaleNoteVisible: !!(staleZipNote && !staleZipNote.classList.contains("hidden")),
      generateBtnLabel: generateBtn ? generateBtn.textContent : null,
    }),
    getScanAgainSourceNote: () => ({
      visible: !!(scanAgainSourceNote && !scanAgainSourceNote.classList.contains("hidden")),
      text: scanAgainSourceNote ? scanAgainSourceNote.textContent : null,
    }),
    getLastScanSource: () => lastScanSource,
    setLastScanHandle: (handle) => { lastScanHandle = handle; lastScanSource = "handle"; },
    setLastScanSource: (source) => { lastScanSource = source; },
  };
})();
