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
  const downloadBtn = document.getElementById("downloadBtn");
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

  let lastSanitizedFiles = [];
  let lastReportEntries = [];
  let lastFilesScanned = 0;

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

  chooseBtn.addEventListener("click", () => folderInput.click());
  dropZone.addEventListener("click", (e) => {
    if (e.target === chooseBtn) return;
    // Don't hijack a click on the placeholder-mode toggle (or its label
    // text) into opening the folder picker - only the empty drop area and
    // its instructional text should do that.
    if (e.target.closest(".placeholder-toggle")) return;
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
    dropZone.classList.add("hidden");
    scanningState.classList.remove("hidden");
    resultsState.classList.add("hidden");

    const files = Array.from(fileList);
    scanningText.textContent = `Reading ${files.length} files…`;

    const readable = [];
    let skippedCount = 0;

    for (const file of files) {
      const relPath = file.relativePath || file.webkitRelativePath || file.name;
      if (isBinaryByName(relPath) || file.size > MAX_FILE_BYTES) {
        skippedCount++;
        continue;
      }
      try {
        const content = await readFileAsText(file);
        readable.push({ path: relPath, content });
      } catch (e) {
        skippedCount++;
      }
    }

    scanningText.textContent = `Scanning ${readable.length} files…`;
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

    lastSanitizedFiles = scanResult.sanitizedFiles;
    lastReportEntries = scanResult.reportEntries;
    lastFilesScanned = readable.length;

    // Also carry through skipped (binary/oversized) files into the zip, untouched,
    // so the downloaded copy is a complete mirror of the original folder.
    for (const file of files) {
      const relPath = file.relativePath || file.webkitRelativePath || file.name;
      if (isBinaryByName(relPath) || file.size > MAX_FILE_BYTES) {
        lastSanitizedFiles.push({ path: relPath, content: file, binary: true, rawFile: true });
      }
    }

    renderResults(lastFilesScanned, lastReportEntries);

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
      html += `<div class="result-row">
        <div class="result-line">${e.line}</div>
        <div class="result-file" title="${escapeHtml(e.file)}">${escapeHtml(e.file)}</div>
        <div class="result-rule">${escapeHtml(e.rule)}${changedBadge}</div>
        <div class="result-key">${escapeHtml(e.key || "—")}</div>
        <div class="result-action">
          ${storageSupported ? `<button class="ignore-btn" data-index="${i}" title="Remember this exact value as a known false positive/accepted risk on this device only">Ignore</button>` : ""}
        </div>
      </div>`;
    });
    resultsTable.innerHTML = html;
  }

  resultsTable.addEventListener("click", async (e) => {
    const btn = e.target.closest(".ignore-btn");
    if (!btn) return;
    const idx = Number(btn.dataset.index);
    const entry = lastReportEntries[idx];
    if (!entry) return;

    const db = await getDb();
    if (!db) return;

    btn.disabled = true;
    btn.textContent = "Ignoring…";

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
    renderResults(lastFilesScanned, lastReportEntries);
  });

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
        <span class="scan-history-date">${escapeHtml(when)}</span>
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

  downloadBtn.addEventListener("click", async () => {
    downloadBtn.disabled = true;
    downloadBtn.textContent = "Building zip…";

    const zip = new JSZip();
    for (const f of lastSanitizedFiles) {
      if (f.rawFile) {
        zip.file(f.path, f.content); // original File object, binary-safe
      } else {
        zip.file(f.path, f.content);
      }
    }
    const blob = await zip.generateAsync({ type: "blob" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "sanitized-project.zip";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    downloadBtn.disabled = false;
    downloadBtn.textContent = "Download sanitized copy (.zip)";
  });

  startOverBtn.addEventListener("click", () => {
    folderInput.value = "";
    lastSanitizedFiles = [];
    lastReportEntries = [];
    lastFilesScanned = 0;
    resultsState.classList.add("hidden");
    dropZone.classList.remove("hidden");
  });

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }
})();
