/**
 * Cadence PII Shield - Enterprise Compliance Controller
 * Hash-Routed SPA: #upload, #processing, #results, #audit
 * Zero emojis, clean state management, fail-closed verification
 */

// Application State
const state = {
    currentRoute: "upload",
    selectedSample: "pptx", // default sample
    uploadedFile: null,
    redactionMode: "tokenization",
    maxPdfPages: 5,
    analysisData: null,
    syncScroll: true,
    viewMode: "split",
    filterType: "ALL",
    filterSource: "ALL",
    filterSearch: ""
};

document.addEventListener("DOMContentLoaded", () => {
    initRouting();
    initUploadPage();
    initProcessingPage();
    initResultsPage();
    initAuditPage();

    // Initialize with default hash or #upload
    const initialHash = window.location.hash.replace("#", "") || "upload";
    navigateTo(initialHash);
});

// ==============================================================================
// 1. HASH ROUTING CONTROLLER
// ==============================================================================

function initRouting() {
    window.addEventListener("hashchange", () => {
        const route = window.location.hash.replace("#", "") || "upload";
        navigateTo(route);
    });

    document.querySelectorAll(".nav-link").forEach(link => {
        link.addEventListener("click", (e) => {
            const target = link.getAttribute("href").replace("#", "");
            navigateTo(target);
        });
    });
}

function navigateTo(route) {
    const validRoutes = ["upload", "processing", "results", "audit"];
    if (!validRoutes.includes(route)) {
        route = "upload";
    }
    state.currentRoute = route;

    // Update Nav Link Active States
    document.querySelectorAll(".nav-link").forEach(l => {
        l.classList.remove("active");
        if (l.getAttribute("href") === `#${route}`) {
            l.classList.add("active");
        }
    });

    // Update Page Views
    document.querySelectorAll(".page-view").forEach(p => p.classList.remove("active"));
    const activePage = document.getElementById(`page-${route}`);
    if (activePage) {
        activePage.classList.add("active");
    }

    // Scroll to top
    window.scrollTo({ top: 0, behavior: "instant" });
}

// ==============================================================================
// 2. PAGE 1: UPLOAD & SAMPLES
// ==============================================================================

function initUploadPage() {
    const sampleCards = document.querySelectorAll(".sample-card");
    const dropzone = document.getElementById("dropzone");
    const fileInput = document.getElementById("fileInput");
    const selectedFileBanner = document.getElementById("selectedFileBanner");
    const selectedFileName = document.getElementById("selectedFileName");
    const btnClearFile = document.getElementById("btnClearSelectedFile");
    const btnModeToken = document.getElementById("btnModeToken");
    const btnModeMask = document.getElementById("btnModeMask");
    const selectPdfPages = document.getElementById("inputPdfPages");
    const btnProcess = document.getElementById("btnProcessDocument");

    // Sample card selection
    sampleCards.forEach(card => {
        card.addEventListener("click", () => {
            sampleCards.forEach(c => c.classList.remove("selected"));
            card.classList.add("selected");
            state.selectedSample = card.getAttribute("data-sample");
            state.uploadedFile = null;
            if (selectedFileBanner) selectedFileBanner.style.display = "none";
        });
    });

    // Mark default PPTX sample selected
    const defaultSample = document.getElementById("sampleCardPptx");
    if (defaultSample) defaultSample.classList.add("selected");

    // Dropzone triggers
    if (dropzone && fileInput) {
        dropzone.addEventListener("click", (e) => {
            if (e.target !== btnClearFile) fileInput.click();
        });

        dropzone.addEventListener("dragover", (e) => {
            e.preventDefault();
            dropzone.classList.add("dragover");
        });

        dropzone.addEventListener("dragleave", () => {
            dropzone.classList.remove("dragover");
        });

        dropzone.addEventListener("drop", (e) => {
            e.preventDefault();
            dropzone.classList.remove("dragover");
            if (e.dataTransfer.files.length > 0) {
                handleFileSelection(e.dataTransfer.files[0]);
            }
        });

        fileInput.addEventListener("change", (e) => {
            if (e.target.files.length > 0) {
                handleFileSelection(e.target.files[0]);
            }
        });
    }

    if (btnClearFile) {
        btnClearFile.addEventListener("click", (e) => {
            e.stopPropagation();
            state.uploadedFile = null;
            if (fileInput) fileInput.value = "";
            if (selectedFileBanner) selectedFileBanner.style.display = "none";
            // Re-select sample card
            if (defaultSample) {
                sampleCards.forEach(c => c.classList.remove("selected"));
                defaultSample.classList.add("selected");
                state.selectedSample = "pptx";
            }
        });
    }

    // Redaction mode toggle
    if (btnModeToken && btnModeMask) {
        btnModeToken.addEventListener("click", () => {
            btnModeToken.classList.add("active");
            btnModeMask.classList.remove("active");
            state.redactionMode = "tokenization";
        });

        btnModeMask.addEventListener("click", () => {
            btnModeMask.classList.add("active");
            btnModeToken.classList.remove("active");
            state.redactionMode = "masking";
        });
    }

    if (selectPdfPages) {
        selectPdfPages.addEventListener("change", () => {
            state.maxPdfPages = parseInt(selectPdfPages.value, 10) || 5;
        });
    }

    // Run Processing Action
    if (btnProcess) {
        btnProcess.addEventListener("click", () => {
            executeDocumentProcessing();
        });
    }
}

function handleFileSelection(file) {
    const allowed = [".pptx", ".docx", ".pdf", ".txt"];
    const ext = file.name.substring(file.name.lastIndexOf(".")).toLowerCase();
    if (!allowed.includes(ext)) {
        alert(`Unsupported file type '${ext}'. Please upload .pptx, .docx, .pdf, or .txt file.`);
        return;
    }
    if (file.size > 50 * 1024 * 1024) {
        alert("File size exceeds 50MB maximum limit.");
        return;
    }

    state.uploadedFile = file;
    state.selectedSample = null;
    document.querySelectorAll(".sample-card").forEach(c => c.classList.remove("selected"));

    const banner = document.getElementById("selectedFileBanner");
    const nameEl = document.getElementById("selectedFileName");
    if (banner && nameEl) {
        nameEl.textContent = file.name;
        banner.style.display = "flex";
    }
}

async function executeDocumentProcessing() {
    showLoading(true, "Processing Document", "Executing structural extraction, neural OCR, and multi-layer detection...");
    navigateTo("processing");
    resetPipelineStepper();

    try {
        let result = null;
        if (state.uploadedFile) {
            const formData = new FormData();
            formData.append("file", state.uploadedFile);
            formData.append("redaction_mode", state.redactionMode);
            formData.append("max_pdf_pages", state.maxPdfPages);

            const res = await fetch("/api/upload", {
                method: "POST",
                body: formData
            });
            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.detail || `Upload failed with HTTP ${res.status}`);
            }
            result = await res.json();
        } else {
            const sampleId = state.selectedSample || "pptx";
            const res = await fetch("/api/process-sample", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    sample_id: sampleId,
                    redaction_mode: state.redactionMode,
                    max_pdf_pages: state.maxPdfPages
                })
            });
            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.detail || `Processing sample failed with HTTP ${res.status}`);
            }
            result = await res.json();
        }

        state.analysisData = result;
        updateGlobalStatus(result);
        populateProcessingPage(result);
        populateResultsPage(result);
        populateAuditPage(result);

        // Auto transition button in processing
        const btnGoResults = document.getElementById("btnViewResultsFromProcessing");
        if (btnGoResults) btnGoResults.style.display = "inline-flex";

    } catch (err) {
        console.error("Processing error:", err);
        alert(`Error processing document: ${err.message}`);
        updateStepperFailure(err.message);
    } finally {
        showLoading(false);
    }
}

// ==============================================================================
// 3. PAGE 2: PROCESSING
// ==============================================================================

function initProcessingPage() {
    const btnGoResults = document.getElementById("btnViewResultsFromProcessing");
    if (btnGoResults) {
        btnGoResults.addEventListener("click", () => {
            navigateTo("results");
        });
    }
}

function resetPipelineStepper() {
    const steps = ["stepIngest", "stepExtract", "stepOcr", "stepDetect", "stepRedact", "stepVerify"];
    steps.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.remove("completed");
    });
    const tag = document.getElementById("pipelineStatusTag");
    if (tag) {
        tag.className = "status-tag status-neutral";
        tag.textContent = "Processing In Progress";
    }
}

function populateProcessingPage(data) {
    const emptyState = document.getElementById("procEmptyState");
    const summaryCard = document.getElementById("procSummaryCard");
    if (emptyState) emptyState.style.display = "none";
    if (summaryCard) summaryCard.style.display = "block";

    // Mark all steps completed
    const steps = ["stepIngest", "stepExtract", "stepOcr", "stepDetect", "stepRedact", "stepVerify"];
    steps.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.add("completed");
    });

    const statusMap = {
        "statusIngest": "Validated",
        "statusExtract": `${data.entities ? data.entities.length : 0} Blocks`,
        "statusOcr": data.metadata?.ocr_activated ? "RapidOCR Triggered" : "Native Text Layer",
        "statusDetect": `${data.entity_count || 0} Entities Found`,
        "statusRedact": "Sanitized Stream Generated",
        "statusVerify": data.verification_status === "PASSED" ? "Passed (0 Residuals)" : "Blocked"
    };

    Object.entries(statusMap).forEach(([id, text]) => {
        const el = document.getElementById(id);
        if (el) el.textContent = text;
    });

    const tag = document.getElementById("pipelineStatusTag");
    if (tag) {
        if (data.verification_status === "PASSED") {
            tag.className = "status-tag status-success";
            tag.textContent = "All Stages Complete - Passed";
        } else {
            tag.className = "status-tag status-danger";
            tag.textContent = "Verification Failed - Blocked";
        }
    }

    // Document Metadata Details
    const docName = document.getElementById("procDocName");
    const docFormat = document.getElementById("procDocFormat");
    const docMethod = document.getElementById("procExtractionMethod");
    const docVerify = document.getElementById("procVerifyResult");

    if (docName) docName.textContent = data.filename || "Unknown";
    if (docFormat) docFormat.textContent = (data.metadata?.format || "document").toUpperCase();
    if (docMethod) docMethod.textContent = data.metadata?.extraction_method || "Native";
    if (docVerify) {
        docVerify.textContent = data.verification_status === "PASSED" ? "Passed (0 Residuals)" : "Blocked (Residuals Detected)";
        docVerify.style.color = data.verification_status === "PASSED" ? "var(--color-success-text)" : "var(--color-danger-text)";
    }

    // PDF Per-Page Ingestion Table
    const pdfCard = document.getElementById("procPdfPagesCard");
    const tbody = document.getElementById("tbodyPdfPages");
    if (pdfCard && tbody) {
        if (data.metadata?.pages_info && data.metadata.pages_info.length > 0) {
            pdfCard.style.display = "block";
            tbody.innerHTML = data.metadata.pages_info.map(p => `
                <tr>
                    <td>Page ${p.page}</td>
                    <td><span class="format-tag ${p.method === 'ocr' ? 'tag-pdf' : 'tag-docx'}">${p.method === 'ocr' ? 'RapidOCR Neural' : 'Native Text'}</span></td>
                    <td><span class="status-tag status-success">Extracted</span></td>
                    <td>${p.method === 'ocr' ? 'Bounding Coordinates Logged' : 'Direct Layout Run'}</td>
                </tr>
            `).join("");
        } else {
            pdfCard.style.display = "none";
        }
    }
}

function updateStepperFailure(msg) {
    const tag = document.getElementById("pipelineStatusTag");
    if (tag) {
        tag.className = "status-tag status-danger";
        tag.textContent = "Execution Error";
    }
    const docVerify = document.getElementById("procVerifyResult");
    if (docVerify) {
        docVerify.textContent = `Error: ${msg}`;
        docVerify.style.color = "var(--color-danger-text)";
    }
}

// ==============================================================================
// 4. PAGE 3: RESULTS (Two-Pane Dual Viewer)
// ==============================================================================

function initResultsPage() {
    const btnViewSplit = document.getElementById("btnViewSplit");
    const btnViewSanitized = document.getElementById("btnViewSanitized");
    const btnViewRaw = document.getElementById("btnViewRaw");
    const btnSyncScroll = document.getElementById("btnToggleSyncScroll");
    const searchInput = document.getElementById("viewerSearchInput");
    const btnCopyStream = document.getElementById("btnCopyStream");
    const btnDownloadSanitized = document.getElementById("btnDownloadSanitized");
    const btnDownloadTxt = document.getElementById("btnDownloadTxt");

    // View modes
    const viewButtons = [btnViewSplit, btnViewSanitized, btnViewRaw];
    viewButtons.forEach(btn => {
        if (!btn) return;
        btn.addEventListener("click", () => {
            viewButtons.forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            const mode = btn.getAttribute("data-view");
            state.viewMode = mode;

            const viewer = document.getElementById("dualViewer");
            if (viewer) {
                viewer.className = `dual-viewer-container mode-${mode}`;
            }
        });
    });

    // Synchronized Scrolling
    if (btnSyncScroll) {
        btnSyncScroll.addEventListener("click", () => {
            state.syncScroll = !state.syncScroll;
            btnSyncScroll.classList.toggle("active", state.syncScroll);
            btnSyncScroll.textContent = `Sync Scroll: ${state.syncScroll ? 'ON' : 'OFF'}`;
        });
    }

    const contentRaw = document.getElementById("contentRaw");
    const contentSanitized = document.getElementById("contentSanitized");
    const gutterRaw = document.getElementById("gutterRaw");
    const gutterSanitized = document.getElementById("gutterSanitized");

    let isSyncingScroll = false;
    if (contentRaw && contentSanitized) {
        contentRaw.addEventListener("scroll", () => {
            if (gutterRaw) gutterRaw.scrollTop = contentRaw.scrollTop;
            if (state.syncScroll && !isSyncingScroll) {
                isSyncingScroll = true;
                const ratio = contentRaw.scrollTop / (contentRaw.scrollHeight - contentRaw.clientHeight || 1);
                contentSanitized.scrollTop = ratio * (contentSanitized.scrollHeight - contentSanitized.clientHeight || 1);
                if (gutterSanitized) gutterSanitized.scrollTop = contentSanitized.scrollTop;
                isSyncingScroll = false;
            }
        });

        contentSanitized.addEventListener("scroll", () => {
            if (gutterSanitized) gutterSanitized.scrollTop = contentSanitized.scrollTop;
            if (state.syncScroll && !isSyncingScroll) {
                isSyncingScroll = true;
                const ratio = contentSanitized.scrollTop / (contentSanitized.scrollHeight - contentSanitized.clientHeight || 1);
                contentRaw.scrollTop = ratio * (contentRaw.scrollHeight - contentRaw.clientHeight || 1);
                if (gutterRaw) gutterRaw.scrollTop = contentRaw.scrollTop;
                isSyncingScroll = false;
            }
        });
    }

    // Search filter across panes
    if (searchInput) {
        searchInput.addEventListener("input", () => {
            applyViewerSearch(searchInput.value.trim());
        });
    }

    // Copy stream button
    if (btnCopyStream) {
        btnCopyStream.addEventListener("click", () => {
            if (state.analysisData && state.analysisData.sanitized_text) {
                navigator.clipboard.writeText(state.analysisData.sanitized_text).then(() => {
                    const origText = btnCopyStream.textContent;
                    btnCopyStream.textContent = "Copied!";
                    setTimeout(() => { btnCopyStream.textContent = origText; }, 2000);
                });
            }
        });
    }

    // Download actions
    if (btnDownloadSanitized) {
        btnDownloadSanitized.addEventListener("click", () => {
            downloadRedactedDocument("native");
        });
    }

    if (btnDownloadTxt) {
        btnDownloadTxt.addEventListener("click", () => {
            downloadRedactedDocument("txt");
        });
    }
}

function populateResultsPage(data) {
    // Ribbon Header Real Counts
    const ribbonRaw = document.getElementById("ribbonRawCount");
    const ribbonTransform = document.getElementById("ribbonTransformMethod");
    const ribbonVerify = document.getElementById("ribbonVerifyStatus");

    if (ribbonRaw) ribbonRaw.textContent = `${data.entity_count || 0} Entities Detected`;
    if (ribbonTransform) {
        ribbonTransform.textContent = state.redactionMode === "tokenization" 
            ? "Deterministic HMAC-SHA256 Tokenization" 
            : "Full Solid Box Masking";
    }
    if (ribbonVerify) {
        if (data.verification_status === "PASSED") {
            ribbonVerify.className = "ribbon-val ribbon-success";
            ribbonVerify.textContent = "0 Residual Findings • Passed";
        } else {
            const count = data.audit_report?.residuals?.length || 1;
            ribbonVerify.className = "ribbon-val ribbon-danger";
            ribbonVerify.textContent = `${count} Residual Findings • Blocked`;
        }
    }

    // Left Pane (Raw)
    const rawBadge = document.getElementById("rawFormatBadge");
    const rawExp = document.getElementById("rawExposureCount");
    const contentRaw = document.getElementById("contentRaw");
    const gutterRaw = document.getElementById("gutterRaw");

    if (rawBadge) rawBadge.textContent = (data.metadata?.format || "DOC").toUpperCase();
    if (rawExp) rawExp.textContent = `${data.entity_count || 0} PII Exposures`;
    if (contentRaw) {
        contentRaw.innerHTML = renderAnnotatedRawText(data.raw_text || "", data.entities || []);
    }
    if (gutterRaw && contentRaw) {
        generateLineGutter(gutterRaw, data.raw_text || "");
    }

    // Right Pane (Sanitized)
    const gateTag = document.getElementById("sanitizedGateTag");
    const tokenBadge = document.getElementById("sanitizedTokenCount");
    const contentSanitized = document.getElementById("contentSanitized");
    const gutterSanitized = document.getElementById("gutterSanitized");

    if (gateTag) {
        gateTag.className = data.verification_status === "PASSED" 
            ? "tag-status-small tag-status-success" 
            : "tag-status-small tag-status-danger";
        gateTag.textContent = data.verification_status;
    }
    if (tokenBadge) {
        tokenBadge.textContent = `${Object.keys(data.entity_map || {}).length} Tokens`;
    }
    if (contentSanitized) {
        contentSanitized.innerHTML = renderAnnotatedSanitizedText(data.sanitized_text || "");
    }
    if (gutterSanitized && contentSanitized) {
        generateLineGutter(gutterSanitized, data.sanitized_text || "");
    }
}

function renderAnnotatedRawText(rawText, entities) {
    if (!rawText) return "No raw artifact text available.";
    let safe = escapeHtml(rawText);

    // Render Slide and Page banners
    safe = safe.replace(/--- \[SLIDE (\d+)\] ---/g, '<span class="stream-banner slide">Slide $1</span>');
    safe = safe.replace(/--- \[PAGE (\d+)\] ---/g, '<span class="stream-banner page">Page $1</span>');
    safe = safe.replace(/--- \[METADATA\] ---/g, '<span class="stream-banner metadata">Document Metadata</span>');

    return safe;
}

function renderAnnotatedSanitizedText(sanitizedText) {
    if (!sanitizedText) return "No sanitized stream available.";
    let safe = escapeHtml(sanitizedText);

    // Format Tokens with square-cornered chips
    safe = safe.replace(/(\[[A-Z0-9_]{3,}_[a-f0-9]{4,12}\])/g, '<span class="sanitized-token-chip">$1</span>');

    // Format Banners
    safe = safe.replace(/--- \[SLIDE (\d+)\] ---/g, '<span class="stream-banner slide">Slide $1</span>');
    safe = safe.replace(/--- \[PAGE (\d+)\] ---/g, '<span class="stream-banner page">Page $1</span>');
    safe = safe.replace(/--- \[METADATA\] ---/g, '<span class="stream-banner metadata">Document Metadata</span>');

    return safe;
}

function generateLineGutter(gutterEl, text) {
    const lineCount = (text.match(/\n/g) || []).length + 1;
    let numbers = "";
    for (let i = 1; i <= lineCount; i++) {
        numbers += `${i}\n`;
    }
    gutterEl.textContent = numbers;
}

function applyViewerSearch(query) {
    const rawEl = document.getElementById("contentRaw");
    const sanEl = document.getElementById("contentSanitized");
    if (!state.analysisData) return;

    if (!query) {
        populateResultsPage(state.analysisData);
        return;
    }

    const reg = new RegExp(`(${escapeRegex(query)})`, "gi");
    if (rawEl) {
        const rawAnnotated = renderAnnotatedRawText(state.analysisData.raw_text || "", state.analysisData.entities || []);
        rawEl.innerHTML = rawAnnotated.replace(reg, '<mark style="background-color: #FEF08A; color: #854D0E;">$1</mark>');
    }
    if (sanEl) {
        const sanAnnotated = renderAnnotatedSanitizedText(state.analysisData.sanitized_text || "");
        sanEl.innerHTML = sanAnnotated.replace(reg, '<mark style="background-color: #FEF08A; color: #854D0E;">$1</mark>');
    }
}

async function downloadRedactedDocument(exportFormat) {
    if (!state.analysisData) {
        alert("No processed document available to download.");
        return;
    }

    try {
        const res = await fetch("/api/download-redacted", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                filename: state.analysisData.filename,
                sanitized_text: state.analysisData.sanitized_text,
                export_format: exportFormat
            })
        });

        if (!res.ok) {
            throw new Error(`Download failed with status ${res.status}`);
        }

        const blob = await res.blob();
        const disp = res.headers.get("Content-Disposition");
        let filename = state.analysisData.filename;
        if (disp && disp.includes("filename=")) {
            filename = disp.split("filename=")[1].replace(/["']/g, "").trim();
        } else if (exportFormat === "txt") {
            filename = filename.replace(/\.[^/.]+$/, "") + "_REDACTED.txt";
        }

        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    } catch (err) {
        alert(`Error downloading redacted file: ${err.message}`);
    }
}

// ==============================================================================
// 5. PAGE 4: FINDINGS & AUDIT
// ==============================================================================

function initAuditPage() {
    const filterType = document.getElementById("filterEntityType");
    const filterSource = document.getElementById("filterSource");
    const filterSearch = document.getElementById("filterSearch");
    const btnExportJson = document.getElementById("btnExportAuditJson");
    const btnExportCsv = document.getElementById("btnExportAuditCsv");

    if (filterType) {
        filterType.addEventListener("change", () => {
            state.filterType = filterType.value;
            renderAuditFindingsTable();
        });
    }

    if (filterSource) {
        filterSource.addEventListener("change", () => {
            state.filterSource = filterSource.value;
            renderAuditFindingsTable();
        });
    }

    if (filterSearch) {
        filterSearch.addEventListener("input", () => {
            state.filterSearch = filterSearch.value.trim().toLowerCase();
            renderAuditFindingsTable();
        });
    }

    if (btnExportJson) {
        btnExportJson.addEventListener("click", () => {
            exportAuditReport("json");
        });
    }

    if (btnExportCsv) {
        btnExportCsv.addEventListener("click", () => {
            exportAuditReport("csv");
        });
    }
}

function populateAuditPage(data) {
    // Metric summaries
    const mTotal = document.getElementById("auditMetricTotal");
    const mNames = document.getElementById("auditMetricNames");
    const mContacts = document.getElementById("auditMetricContacts");
    const mIds = document.getElementById("auditMetricIds");
    const mStructure = document.getElementById("auditMetricStructure");
    const mStatus = document.getElementById("auditMetricStatus");
    const mResidualCount = document.getElementById("auditMetricResidualCount");

    const entities = data.entities || [];
    const nameCount = entities.filter(e => e.type === "PERSON_NAME").length;
    const contactCount = entities.filter(e => e.type === "EMAIL" || e.type === "PHONE_NUMBER").length;
    const idCount = entities.filter(e => ["EMPLOYEE_ID", "USER_ID", "CONTRACT_OP_ID", "SSN", "PAN_GOV_ID", "PESEL_GOV_ID"].includes(e.type)).length;

    if (mTotal) mTotal.textContent = data.entity_count || 0;
    if (mNames) mNames.textContent = nameCount;
    if (mContacts) mContacts.textContent = contactCount;
    if (mIds) mIds.textContent = idCount;
    if (mStructure) mStructure.textContent = `${data.structure_score || 100}%`;
    if (mStatus) {
        mStatus.textContent = data.verification_status;
        mStatus.style.color = data.verification_status === "PASSED" ? "var(--color-success-text)" : "var(--color-danger-text)";
    }

    const residuals = data.audit_report?.residuals || [];
    if (mResidualCount) {
        mResidualCount.textContent = `${residuals.length} residual findings`;
    }

    // Residuals Alert Box
    const resBadge = document.getElementById("auditVerificationBadge");
    const resContainer = document.getElementById("residualsContainer");

    if (resBadge) {
        resBadge.className = data.verification_status === "PASSED" ? "status-tag status-success" : "status-tag status-danger";
        resBadge.textContent = data.verification_status;
    }

    if (resContainer) {
        if (residuals.length === 0) {
            resContainer.innerHTML = '<p class="text-muted" style="padding: 0.5rem 0;">Zero residual findings detected across independent regex passes, token fragmentation tests, and pass-1 value hash checks. Status: PASSED.</p>';
        } else {
            resContainer.innerHTML = `
                <div style="color: var(--color-danger-text); font-weight: 600; margin-bottom: 0.5rem;">
                    Fail-Closed Policy Violation: ${residuals.length} residual credential(s) detected. Document release is BLOCKED.
                </div>
                <table class="residuals-table">
                    <thead>
                        <tr>
                            <th>Residual Type</th>
                            <th>Location</th>
                            <th>Value Hash</th>
                            <th>Detection Justification</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${residuals.map(r => `
                            <tr>
                                <td><span class="status-tag status-danger">${escapeHtml(r.type)}</span></td>
                                <td>${escapeHtml(r.location)}</td>
                                <td><code>${escapeHtml(r.value_hash)}</code></td>
                                <td>${escapeHtml(r.reason)}</td>
                            </tr>
                        `).join("")}
                    </tbody>
                </table>
            `;
        }
    }

    renderAuditFindingsTable();
}

function renderAuditFindingsTable() {
    const tbody = document.getElementById("tbodyFindings");
    if (!tbody || !state.analysisData) return;

    let findings = state.analysisData.audit_report?.detailed_findings || state.analysisData.entities || [];

    // Filter by type
    if (state.filterType !== "ALL") {
        if (state.filterType === "OTHER") {
            const common = ["PERSON_NAME", "EMAIL", "PHONE_NUMBER", "EMPLOYEE_ID", "USER_ID"];
            findings = findings.filter(f => !common.includes(f.type));
        } else {
            findings = findings.filter(f => f.type === state.filterType);
        }
    }

    // Filter by source
    if (state.filterSource !== "ALL") {
        findings = findings.filter(f => (f.source || "native").toLowerCase() === state.filterSource);
    }

    // Search filter
    if (state.filterSearch) {
        findings = findings.filter(f => {
            const token = (f.token || "").toLowerCase();
            const hash = (f.value_hash || "").toLowerCase();
            const reason = (f.reason || "").toLowerCase();
            return token.includes(state.filterSearch) || hash.includes(state.filterSearch) || reason.includes(state.filterSearch);
        });
    }

    if (findings.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted" style="padding: 2rem;">No matching findings for the selected filter criteria.</td></tr>';
        return;
    }

    tbody.innerHTML = findings.map(f => `
        <tr>
            <td><code>#${f.id}</code></td>
            <td><span class="legend-tag tag-control-id">${escapeHtml(f.type)}</span></td>
            <td><span class="sanitized-token-chip">${escapeHtml(f.token || "-")}</span></td>
            <td><code>${escapeHtml(f.value_hash || "-")}</code></td>
            <td><span class="format-tag ${(f.source || 'native') === 'ocr' ? 'tag-pdf' : 'tag-docx'}">${escapeHtml(f.source || "native")}</span></td>
            <td><span class="status-tag ${f.severity === 'CRITICAL' ? 'status-danger' : 'status-neutral'}">${escapeHtml(f.severity || "HIGH")}</span></td>
            <td>${Math.round((f.confidence || 0.95) * 100)}%</td>
            <td style="font-size: 0.78rem;">${escapeHtml(f.reason || "Contextual rule match")}</td>
        </tr>
    `).join("");
}

async function exportAuditReport(format) {
    if (!state.analysisData) {
        alert("No audit data available to export.");
        return;
    }

    try {
        const res = await fetch("/api/export-audit", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                filename: state.analysisData.filename,
                audit_report: state.analysisData.audit_report,
                export_format: format
            })
        });

        if (!res.ok) throw new Error(`Export failed with HTTP ${res.status}`);

        const blob = await res.blob();
        const baseName = state.analysisData.filename.replace(/\.[^/.]+$/, "");
        const ext = format === "csv" ? "csv" : "json";
        const downloadName = `AUDIT_EXPOSURE_REPORT_${baseName}.${ext}`;

        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = downloadName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    } catch (err) {
        alert(`Error exporting audit: ${err.message}`);
    }
}

// ==============================================================================
// 6. UTILITIES & HELPERS
// ==============================================================================

function updateGlobalStatus(data) {
    const dot = document.getElementById("headerStatusDot");
    const nameEl = document.getElementById("headerDocName");

    if (dot && nameEl) {
        dot.className = "status-indicator-dot";
        if (data.verification_status === "PASSED") {
            dot.classList.add("active-passed");
            nameEl.textContent = `${data.filename} (Passed)`;
        } else {
            dot.classList.add("active-blocked");
            nameEl.textContent = `${data.filename} (Blocked)`;
        }
    }
}

function showLoading(show, title = "Processing Document", subtitle = "Extracting text and scanning for PII...") {
    const overlay = document.getElementById("loadingOverlay");
    const titleEl = document.getElementById("loadingTitle");
    const subEl = document.getElementById("loadingSubtitle");

    if (overlay) {
        overlay.style.display = show ? "flex" : "none";
        if (titleEl) titleEl.textContent = title;
        if (subEl) subEl.textContent = subtitle;
    }
}

function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
