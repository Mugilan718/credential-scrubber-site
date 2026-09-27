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

  let lastSanitizedFiles = [];

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
    const { sanitizedFiles, reportEntries } = scanFiles(readable, { placeholderMode });
    lastSanitizedFiles = sanitizedFiles;

    // Also carry through skipped (binary/oversized) files into the zip, untouched,
    // so the downloaded copy is a complete mirror of the original folder.
    for (const file of files) {
      const relPath = file.relativePath || file.webkitRelativePath || file.name;
      if (isBinaryByName(relPath) || file.size > MAX_FILE_BYTES) {
        lastSanitizedFiles.push({ path: relPath, content: file, binary: true, rawFile: true });
      }
    }

    renderResults(readable.length, reportEntries);
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
    entries.forEach((e) => {
      html += `<div class="result-row">
        <div class="result-line">${e.line}</div>
        <div class="result-file" title="${escapeHtml(e.file)}">${escapeHtml(e.file)}</div>
        <div class="result-rule">${escapeHtml(e.rule)}</div>
        <div class="result-key">${escapeHtml(e.key || "—")}</div>
      </div>`;
    });
    resultsTable.innerHTML = html;
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
    resultsState.classList.add("hidden");
    dropZone.classList.remove("hidden");
  });

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }
})();
