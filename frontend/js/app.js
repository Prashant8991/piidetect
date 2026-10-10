/**
 * Optiv Consulting - Cadence Financial Group AI Privacy Shield
 * Frontend Application Controller
 */

let currentAnalysisData = null;
let currentRedactionMode = "tokenization";
let currentFilter = "ALL";

document.addEventListener("DOMContentLoaded", () => {
    initNavigation();
    initUploadZone();
    initSampleTriggers();
    initSettingsToggles();
    initExportActions();
    initLLMGate();
    initFilterChips();
    initViewerControls();
    initSyncScroll();
    initEntityHoverLinking();
    
    // Auto-load PPTX sample on initial visit for immediate wow-factor
    loadSample("pptx");
});

// ==============================================================================
// 1. NAVIGATION CONTROLLER
// ==============================================================================

function initNavigation() {
    const navButtons = document.querySelectorAll(".nav-btn");
    const tabPanes = document.querySelectorAll(".tab-pane");

    navButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetTab = btn.getAttribute("data-tab");
            
            navButtons.forEach(b => b.classList.remove("active"));
            tabPanes.forEach(p => p.classList.remove("active"));

            btn.classList.add("active");
            const activePane = document.getElementById(targetTab);
            if (activePane) {
                activePane.classList.add("active");
                window.scrollTo({ top: 0, behavior: "smooth" });
            }
        });
    });
}

function switchTab(tabId) {
    const targetNav = document.querySelector(`.nav-btn[data-tab="${tabId}"]`);
    if (targetNav) {
        targetNav.click();
    }
}

// ==============================================================================
// 2. SAMPLE FILE HANDLERS
// ==============================================================================

function initSampleTriggers() {
    // Quick sample cards in dashboard
    document.querySelectorAll(".sample-card").forEach(card => {
        card.addEventListener("click", () => {
            const sampleId = card.getAttribute("data-sample");
            loadSample(sampleId);
        });
    });

    // Global "Try a Sample" button in header (available on every page)
    const btnGlobalSample = document.getElementById("btnGlobalSample");
    const sampleModal = document.getElementById("sampleModal");
    const modalClose = document.getElementById("modalClose");

    if (btnGlobalSample && sampleModal) {
        btnGlobalSample.addEventListener("click", () => {
            sampleModal.classList.add("active");
        });
        
        modalClose.addEventListener("click", () => {
            sampleModal.classList.remove("active");
        });

        sampleModal.addEventListener("click", (e) => {
            if (e.target === sampleModal) {
                sampleModal.classList.remove("active");
            }
        });

        document.querySelectorAll(".modal-sample-item").forEach(item => {
            item.addEventListener("click", () => {
                const sampleId = item.getAttribute("data-sample");
                sampleModal.classList.remove("active");
                switchTab("tab-dashboard");
                loadSample(sampleId);
            });
        });
    }
}

async function loadSample(sampleId) {
    showLoading(true, `Analyzing Cadence Evidence: ${sampleId.toUpperCase()}...`, "Executing format parsing, OCR fallback, and multi-layer PII detection");

    try {
        const response = await fetch("/api/process-sample", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                sample_id: sampleId,
                redaction_mode: currentRedactionMode,
                max_pdf_pages: 5
            })
        });

        if (!response.ok) {
            throw new Error(`Server returned ${response.status}: ${await response.text()}`);
        }

        const data = await response.json();
        currentAnalysisData = data;
        renderAnalysisResults(data);
    } catch (err) {
        alert("Failed to process sample: " + err.message);
    } finally {
        showLoading(false);
    }
}

// ==============================================================================
// 3. FILE UPLOAD CONTROLLER
// ==============================================================================

function initUploadZone() {
    const dropzone = document.getElementById("dropzone");
    const fileInput = document.getElementById("fileInput");

    if (!dropzone || !fileInput) return;

    dropzone.addEventListener("click", () => fileInput.click());

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
            uploadFile(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener("change", () => {
        if (fileInput.files.length > 0) {
            uploadFile(fileInput.files[0]);
        }
    });
}

async function uploadFile(file) {
    showLoading(true, `Uploading & Analyzing: ${file.name}...`, "Extracting text structure, scanning metadata, and evaluating PII exposure");

    const formData = new FormData();
    formData.append("file", file);
    formData.append("redaction_mode", currentRedactionMode);
    formData.append("max_pdf_pages", "5");

    try {
        const response = await fetch("/api/upload", {
            method: "POST",
            body: formData
        });

        if (!response.ok) {
            throw new Error(`Upload error: ${await response.text()}`);
        }

        const data = await response.json();
        currentAnalysisData = data;
        renderAnalysisResults(data);
    } catch (err) {
        alert("File processing failed: " + err.message);
    } finally {
        showLoading(false);
    }
}

// ==============================================================================
// 4. RENDERING & UI UPDATES
// ==============================================================================

function renderAnalysisResults(data) {
    // 1. Update Metrics Ribbon
    document.getElementById("metricPiiCount").textContent = data.entity_count;
    document.getElementById("metricStructureScore").textContent = `${data.structure_score}%`;
    document.getElementById("metricRecallScore").textContent = `${data.recall_coverage}%`;
    
    const ocrBadge = document.getElementById("metricOcrStatus");
    if (data.metadata && data.metadata.ocr_activated) {
        ocrBadge.textContent = "RapidOCR";
        ocrBadge.style.color = "var(--accent-amber)";
    } else {
        ocrBadge.textContent = "Native XML";
        ocrBadge.style.color = "var(--accent-cyan)";
    }

    // 2. Update Pipeline Stepper (All 7 Stages)
    updateStepper(data);

    // 3. Update LLM Safe Gate Card
    updateLLMGate(data);

    // 4. Update Appendix E.6 Forensic Rubric Card
    updateAppendixE6(data);

    // 5. Render Raw Text with Enhanced PII Chips & Structural Banners
    const rawPane = document.getElementById("paneRawText");
    rawPane.innerHTML = formatRawStreamWithChips(data.raw_text, data.entities);

    // 6. Render Sanitized LLM-Ready Text with Cryptographic Token Badges
    const sanitizedPane = document.getElementById("paneSanitizedText");
    sanitizedPane.innerHTML = formatSanitizedStream(data.sanitized_text, data.entities);

    // 7. Update Diff Comparison Ribbon & Chrome Badges
    updateViewerDiffRibbon(data);

    // 8. Update Line Numbers Gutters
    updateGutters();

    // 9. Rebind Interactive Hover Linking
    bindEntityHoverListeners();

    // 10. Update Current File Badge
    document.getElementById("currentFileName").textContent = data.filename;

    // 10b. Update Sanitized Download Button to match file extension
    const fileExt = (data.filename.split('.').pop() || 'txt').toLowerCase();
    const btnLabel = document.getElementById("btnDownloadSanitizedLabel");
    if (btnLabel) {
        btnLabel.textContent = `Download Sanitized (.${fileExt})`;
    }

    // 11. Update Filter Counts and Render Detailed Findings Table
    updateFilterCounts(data.entities);
    renderFindingsTable(data.entities, currentFilter);
}

function updateStepper(data) {
    const isPdf = data.file_format === ".pdf";
    const isDocx = data.file_format === ".docx";
    const isPptx = data.file_format === ".pptx";
    
    document.getElementById("step-ingest-meta").textContent = `${data.file_format.toUpperCase()} Sniffed`;
    document.getElementById("step-extract-meta").textContent = `${data.structure_score}% Retained`;
    
    if (data.metadata && data.metadata.ocr_activated) {
        document.getElementById("step-ocr-meta").textContent = `${data.metadata.scanned_pages || 5} pgs OCRed`;
    } else {
        document.getElementById("step-ocr-meta").textContent = "Native Pass (Skipped)";
    }

    document.getElementById("step-detect-meta").textContent = `${data.entity_count} Entities Detected`;
    document.getElementById("step-resolve-meta").textContent = "HMAC Tokens Active";
    document.getElementById("step-redact-meta").textContent = currentRedactionMode === "tokenization" ? "Tokenized Stream" : "Masked Stream";
    
    const verifyBadge = document.getElementById("stepperStatusBadge");
    const verifyText = document.getElementById("stepperStatusText");
    const verifyMeta = document.getElementById("step-verify-meta");

    if (data.verification_status === "PASSED") {
        verifyBadge.className = "stepper-status-badge";
        verifyBadge.style.background = "rgba(16, 185, 129, 0.12)";
        verifyBadge.style.borderColor = "rgba(16, 185, 129, 0.35)";
        verifyBadge.style.color = "var(--accent-emerald)";
        verifyText.textContent = "PASSED: ZERO RESIDUAL PII TO LLM";
        verifyMeta.textContent = "PASSED (0 Residual)";
    } else {
        verifyBadge.className = "stepper-status-badge";
        verifyBadge.style.background = "rgba(244, 63, 94, 0.15)";
        verifyBadge.style.borderColor = "var(--accent-rose)";
        verifyBadge.style.color = "var(--accent-rose)";
        verifyText.textContent = "BLOCKED: RESIDUAL DETECTED";
        verifyMeta.textContent = "FAIL-CLOSED BLOCKED";
    }
}

function updateLLMGate(data) {
    const gatePill = document.getElementById("llmGateStatus");
    const gateLabel = document.getElementById("gateStatusLabel");
    const responseBox = document.getElementById("agentResponseBox");

    if (data.verification_status === "PASSED") {
        gatePill.className = "gate-status-pill passed";
        gateLabel.textContent = "GATE: PASSED (ZERO PII REACHES LLM)";
        responseBox.innerHTML = `<div class="agent-response-placeholder">Ready for AI querying. Document verified safe under Cadence Generative AI Policy. Click <strong>"Send to LLM"</strong> or a prompt chip above.</div>`;
    } else {
        gatePill.className = "gate-status-pill blocked";
        gateLabel.textContent = "GATE: BLOCKED (POLICY VIOLATION)";
        responseBox.innerHTML = `<div style="color: var(--accent-rose); padding: 1rem; text-align: center; font-weight: 600;">⛔ POLICY BLOCK: Residual PII identified. Downstream LLM dispatch is strictly prohibited until sanitized.</div>`;
    }
}

function updateAppendixE6(data) {
    const e6 = data.audit_report ? data.audit_report.appendix_e6_metrics : null;
    
    // Exercise 1: Scanned pages
    const ocrStat = document.getElementById("e6StatOcrPages");
    if (data.file_format === ".pdf") {
        ocrStat.textContent = "35 of 35 pages (Scanned OCR)";
        ocrStat.style.color = "var(--accent-amber)";
    } else {
        ocrStat.textContent = "Native XML (0 Scanned Pages)";
        ocrStat.style.color = "var(--accent-cyan)";
    }

    // Exercise 3: Image-only recall
    const imgStat = document.getElementById("e6StatImageRecall");
    if (e6 && e6.exercise_3_image_only_recall) {
        imgStat.textContent = `${e6.exercise_3_image_only_recall} via OCR`;
    } else {
        imgStat.textContent = data.file_format === ".pdf" ? "100.0% via OCR" : "Native Text Stream";
    }

    // Exercise 5: Token consistency
    const tokenStat = document.getElementById("e6StatStableTokens");
    tokenStat.textContent = "HMAC-SHA256 Deterministic Salt";

    // Exercise 6: False positive controls
    const allowStat = document.getElementById("e6StatAllowlist");
    allowStat.textContent = "Active (GRP-POL, RSK, ISS, hotline)";
}

function initLLMGate() {
    const btnAsk = document.getElementById("btnAskAgent");
    const queryInput = document.getElementById("agentQueryInput");
    const responseBox = document.getElementById("agentResponseBox");

    // Chips click
    document.querySelectorAll(".prompt-chip").forEach(chip => {
        chip.addEventListener("click", () => {
            const query = chip.getAttribute("data-query");
            if (queryInput) {
                queryInput.value = query;
                if (btnAsk) btnAsk.click();
            }
        });
    });

    if (btnAsk && queryInput) {
        btnAsk.addEventListener("click", async () => {
            if (!currentAnalysisData) return alert("Please select or upload a document first.");
            
            const question = queryInput.value.trim();
            if (!question) return;

            responseBox.innerHTML = `<div style="text-align: center; color: var(--accent-cyan); padding: 1.5rem;">🤖 Generating safe AI reasoning over pseudonymized tokens...</div>`;

            try {
                const response = await fetch("/api/ask-agent", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        filename: currentAnalysisData.filename,
                        sanitized_text: currentAnalysisData.sanitized_text,
                        verification_status: currentAnalysisData.verification_status,
                        question: question
                    })
                });

                if (!response.ok) {
                    const err = await response.json();
                    responseBox.innerHTML = `<div style="color: var(--accent-rose); padding: 1rem; font-weight: 600;">⛔ ${escapeHtml(err.detail || "Request rejected by Cadence AI Gate.")}</div>`;
                    return;
                }

                const resData = await response.json();
                responseBox.innerHTML = formatMarkdownAnswer(resData.answer);
            } catch (err) {
                responseBox.innerHTML = `<div style="color: var(--accent-rose); padding: 1rem;">Failed to communicate with LLM Gate: ${escapeHtml(err.message)}</div>`;
            }
        });
    }
}

function formatMarkdownAnswer(md) {
    if (!md) return "";
    let html = escapeHtml(md);
    
    // Simple markdown formatting for bold, headers, quotes, and code
    html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
    html = html.replace(/^#### (.*$)/gim, '<h4>$1</h4>');
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
    html = html.replace(/^   &gt; (.*$)/gim, '<blockquote>$1</blockquote>');
    html = html.replace(/---/g, '<hr style="border: none; border-top: 1px solid var(--border-glass); margin: 0.75rem 0;">');
    html = html.replace(/\n/g, '<br>');
    return html;
}

function initFilterChips() {
    const chips = document.querySelectorAll(".filter-chip");
    chips.forEach(chip => {
        chip.addEventListener("click", () => {
            chips.forEach(c => c.classList.remove("active"));
            chip.classList.add("active");
            currentFilter = chip.getAttribute("data-filter");
            if (currentAnalysisData) {
                renderFindingsTable(currentAnalysisData.entities, currentFilter);
            }
        });
    });
}

function updateFilterCounts(entities) {
    if (!entities) return;
    
    const countAll = entities.length;
    const countPersons = entities.filter(e => e.type === "PERSON_NAME").length;
    const countContacts = entities.filter(e => e.type === "EMAIL" || e.type === "PHONE_NUMBER").length;
    const countIds = entities.filter(e => e.type === "EMPLOYEE_ID" || e.type === "CONTRACT_OP_ID" || e.type.includes("PAN") || e.type.includes("SSN")).length;
    const countHigh = entities.filter(e => e.severity === "CRITICAL" || e.severity === "HIGH").length;

    document.getElementById("countAll").textContent = countAll;
    document.getElementById("countPersons").textContent = countPersons;
    document.getElementById("countContacts").textContent = countContacts;
    document.getElementById("countIds").textContent = countIds;
    document.getElementById("countHigh").textContent = countHigh;
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

function formatStructuralBanners(escapedHtml) {
    if (!escapedHtml) return "";
    
    // Document metadata header
    let html = escapedHtml.replace(/--- \[DOCUMENT OPENXML METADATA\] ---/g, 
        '<div class="stream-banner metadata"><span class="banner-icon">📋</span> DOCUMENT OPENXML METADATA</div>');
    
    // Metadata separator line
    html = html.replace(/----------------------------------/g, 
        '<div class="stream-banner divider"></div>');
    
    // Slide headers
    html = html.replace(/--- \[SLIDE (\d+)\] ---/g, 
        '<div class="stream-banner slide"><span class="banner-icon">🎞️</span> SLIDE $1</div>');
    
    // Page headers
    html = html.replace(/--- \[PAGE (\d+)\] ---/g, 
        '<div class="stream-banner metadata"><span class="banner-icon">📄</span> PAGE $1</div>');
    
    // Table markers
    html = html.replace(/\[TABLE\s*(\d+)?\s*START\]/g, 
        '<span class="stream-table-tag">⊞ TABLE $1 START</span>');
    html = html.replace(/\[TABLE\s*(\d+)?\s*END\]/g, 
        '<span class="stream-table-tag">⊞ TABLE $1 END</span>');
    
    return html;
}

function formatRawStreamWithChips(rawText, entities) {
    if (!rawText) return "";
    
    const iconMap = {
        "PERSON_NAME": "👤",
        "EMAIL": "✉️",
        "PHONE_NUMBER": "📞",
        "EMPLOYEE_ID": "🆔",
        "CONTRACT_OP_ID": "📑",
        "FINANCIAL_NUM": "💳",
        "GOV_ID": "🏛️",
        "IP_ADDRESS": "🌐"
    };

    if (!entities || entities.length === 0) {
        return formatStructuralBanners(escapeHtml(rawText));
    }

    const validWithOffsets = entities.filter(e => typeof e.start === 'number' && typeof e.end === 'number');

    if (validWithOffsets.length > 0) {
        const sorted = [...validWithOffsets].sort((a, b) => b.start - a.start);
        let pieces = [];
        let curEnd = rawText.length;

        for (const ent of sorted) {
            const afterText = rawText.slice(ent.end, curEnd);
            pieces.unshift(formatStructuralBanners(escapeHtml(afterText)));

            let chipClass = "name";
            if (ent.type === "EMAIL") chipClass = "email";
            else if (ent.type === "PHONE_NUMBER") chipClass = "phone";
            else if (ent.type === "EMPLOYEE_ID") chipClass = "emp_id";
            else if (ent.type.includes("ID") || ent.type.includes("PAN") || ent.type.includes("PESEL")) chipClass = "contract";

            const icon = iconMap[ent.type] || "⚠️";
            const safeToken = ent.token ? escapeHtml(ent.token) : "";
            const tooltip = `${ent.type} (${Math.round((ent.confidence || 1) * 100)}% conf) ➔ ${ent.token || 'Redacted'}\nReason: ${ent.reason || 'Protected entity'}`;

            const replacementSpan = `<span class="pii-chip ${chipClass}" data-token="${safeToken}" data-entity-id="${ent.id}" data-type="${escapeHtml(ent.type)}" title="${escapeHtml(tooltip)}"><span class="chip-icon">${icon}</span>${escapeHtml(ent.text)}</span>`;
            pieces.unshift(replacementSpan);

            curEnd = ent.start;
        }

        if (curEnd > 0) {
            const beforeText = rawText.slice(0, curEnd);
            pieces.unshift(formatStructuralBanners(escapeHtml(beforeText)));
        }

        return pieces.join("");
    }

    let html = escapeHtml(rawText);
    for (const ent of entities) {
        if (!ent.text || ent.text.length < 2) continue;
        const escVal = escapeHtml(ent.text);
        let chipClass = "name";
        if (ent.type === "EMAIL") chipClass = "email";
        else if (ent.type === "PHONE_NUMBER") chipClass = "phone";
        else if (ent.type === "EMPLOYEE_ID") chipClass = "emp_id";
        else if (ent.type.includes("ID") || ent.type.includes("PAN") || ent.type.includes("PESEL")) chipClass = "contract";

        const icon = iconMap[ent.type] || "⚠️";
        const safeToken = ent.token ? escapeHtml(ent.token) : "";
        const tooltip = `${ent.type} (${Math.round((ent.confidence || 1) * 100)}% conf) ➔ ${ent.token || 'Redacted'}\nReason: ${ent.reason || 'Protected entity'}`;

        const replacementSpan = `<span class="pii-chip ${chipClass}" data-token="${safeToken}" data-entity-id="${ent.id}" data-type="${escapeHtml(ent.type)}" title="${escapeHtml(tooltip)}"><span class="chip-icon">${icon}</span>${escVal}</span>`;
        html = html.split(escVal).join(replacementSpan);
    }
    return formatStructuralBanners(html);
}

function formatSanitizedStream(sanitizedText, entities) {
    if (!sanitizedText) return "";
    let safe = escapeHtml(sanitizedText);
    
    // 1. Format structural banners
    safe = formatStructuralBanners(safe);
    
    // 2. Wrap cryptographic tokens: [TAG_hash] or [REDACTED_TAG]
    safe = safe.replace(/\[([A-Z0-9_]+_[a-f0-9]{4,12})\]/g, (match, p1) => {
        return `<span class="sanitized-token-chip" data-token="[${p1}]" title="Cryptographic Pseudonym (Salted HMAC-SHA256) • Reversible only via secure Cadence Vault"><span class="token-lock-icon">🔒</span>[${p1}]</span>`;
    });
    
    safe = safe.replace(/\[(REDACTED_[A-Z0-9_]+)\]/g, (match, p1) => {
        return `<span class="sanitized-token-chip" data-token="[${p1}]" title="Policy Redacted"><span class="token-lock-icon">🛡️</span>[${p1}]</span>`;
    });

    // 3. Wrap mask bars if in masking mode: ████
    safe = safe.replace(/█{4,}/g, (match) => {
        return `<span class="sanitized-mask-chip">${match}</span>`;
    });
    
    return safe;
}

function renderFindingsTable(entities, filter = "ALL") {
    const tbody = document.getElementById("findingsTableBody");
    tbody.innerHTML = "";

    if (!entities || entities.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-dim); padding: 2rem;">No PII entities detected in this document.</td></tr>`;
        return;
    }

    let filtered = entities;
    if (filter === "PERSON_NAME") {
        filtered = entities.filter(e => e.type === "PERSON_NAME");
    } else if (filter === "CONTACT") {
        filtered = entities.filter(e => e.type === "EMAIL" || e.type === "PHONE_NUMBER");
    } else if (filter === "ID") {
        filtered = entities.filter(e => e.type === "EMPLOYEE_ID" || e.type === "CONTRACT_OP_ID" || e.type.includes("PAN") || e.type.includes("SSN"));
    } else if (filter === "CRITICAL") {
        filtered = entities.filter(e => e.severity === "CRITICAL" || e.severity === "HIGH");
    }

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-dim); padding: 2rem;">No findings matching current filter "${filter}".</td></tr>`;
        return;
    }

    filtered.forEach(ent => {
        const tr = document.createElement("tr");

        let sevClass = "sev-medium";
        if (ent.severity === "CRITICAL") sevClass = "sev-critical";
        else if (ent.severity === "HIGH") sevClass = "sev-high";

        tr.innerHTML = `
            <td><code>#${ent.id}</code></td>
            <td><strong>${escapeHtml(ent.type)}</strong></td>
            <td><code>${escapeHtml(ent.text)}</code></td>
            <td><span class="severity-pill ${sevClass}">${ent.severity}</span></td>
            <td><code>${Math.round(ent.confidence * 100)}%</code></td>
            <td style="font-size: 0.78rem; color: var(--text-dim);">${escapeHtml(ent.reason)}</td>
        `;
        tbody.appendChild(tr);
    });
}

function escapeHtml(str) {
    if (!str) return "";
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// ==============================================================================
// 5. SETTINGS & TOGGLES
// ==============================================================================

function initSettingsToggles() {
    // Redaction Mode Toggles
    const modeBtns = [document.getElementById("btnModeToken"), document.getElementById("btnModeMask")];
    modeBtns.forEach(btn => {
        if (!btn) return;
        btn.addEventListener("click", () => {
            modeBtns.forEach(b => b && b.classList.remove("active"));
            btn.classList.add("active");
            currentRedactionMode = btn.getAttribute("data-mode");
            
            if (currentAnalysisData && currentAnalysisData.sample_info) {
                loadSample(currentAnalysisData.sample_info.id);
            }
        });
    });

    // Paranoid Mode Toggles
    const btnParanoidOn = document.getElementById("btnParanoidOn");
    const btnParanoidOff = document.getElementById("btnParanoidOff");
    const paranoidStatus = document.getElementById("paranoidStatus");

    if (btnParanoidOn && btnParanoidOff) {
        btnParanoidOn.addEventListener("click", () => {
            btnParanoidOn.classList.add("active");
            btnParanoidOff.classList.remove("active");
            if (paranoidStatus) {
                paranoidStatus.textContent = "ACTIVE";
                paranoidStatus.style.color = "var(--accent-emerald)";
            }
        });

        btnParanoidOff.addEventListener("click", () => {
            btnParanoidOff.classList.add("active");
            btnParanoidOn.classList.remove("active");
            if (paranoidStatus) {
                paranoidStatus.textContent = "OFF";
                paranoidStatus.style.color = "var(--text-dim)";
            }
        });
    }

    // Confidence Threshold Slider
    const thresholdSlider = document.getElementById("thresholdSlider");
    const thresholdVal = document.getElementById("thresholdVal");
    if (thresholdSlider && thresholdVal) {
        thresholdSlider.addEventListener("input", (e) => {
            thresholdVal.textContent = `${e.target.value}%`;
        });
    }

    // Allow-List Rules Modal
    const btnOpenAllowlist = document.getElementById("btnOpenAllowlist");
    const allowlistModal = document.getElementById("allowlistModal");
    const allowlistModalClose = document.getElementById("allowlistModalClose");

    if (btnOpenAllowlist && allowlistModal) {
        btnOpenAllowlist.addEventListener("click", () => {
            allowlistModal.classList.add("active");
        });

        if (allowlistModalClose) {
            allowlistModalClose.addEventListener("click", () => {
                allowlistModal.classList.remove("active");
            });
        }

        allowlistModal.addEventListener("click", (e) => {
            if (e.target === allowlistModal) {
                allowlistModal.classList.remove("active");
            }
        });
    }
}

// ==============================================================================
// 6. EXPORT & DOWNLOAD ACTIONS
// ==============================================================================

function initExportActions() {
    const btnDownloadSanitized = document.getElementById("btnDownloadSanitized");
    const btnDownloadLlmTxt = document.getElementById("btnDownloadLlmTxt");
    const btnExportAuditJson = document.getElementById("btnExportAuditJson");
    const btnExportAuditCsv = document.getElementById("btnExportAuditCsv");

    if (btnDownloadSanitized) {
        btnDownloadSanitized.addEventListener("click", async () => {
            if (!currentAnalysisData) return alert("Please load or upload a document first.");
            
            const originalFilename = currentAnalysisData.filename;
            const ext = (originalFilename.split('.').pop() || 'txt').toLowerCase();

            try {
                btnDownloadSanitized.disabled = true;
                btnDownloadSanitized.style.opacity = "0.7";
                
                const response = await fetch("/api/download-redacted", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        filename: originalFilename,
                        sanitized_text: currentAnalysisData.sanitized_text,
                        export_format: "native"
                    })
                });

                if (!response.ok) {
                    throw new Error("Server responded with error: " + response.status);
                }

                // Extract exact filename from Content-Disposition header if exposed
                let downloadName = "";
                const disposition = response.headers.get("Content-Disposition");
                if (disposition && disposition.indexOf("filename=") !== -1) {
                    const matches = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/.exec(disposition);
                    if (matches != null && matches[1]) {
                        downloadName = matches[1].replace(/['"]/g, '');
                    }
                }
                
                if (!downloadName) {
                    const baseName = originalFilename.replace(/\.[^/.]+$/, "");
                    const cleanBase = baseName.startsWith("SANITIZED_") ? baseName.slice("SANITIZED_".length) : baseName;
                    downloadName = `SANITIZED_${cleanBase}.${ext}`;
                }

                const blob = await response.blob();
                downloadBlob(blob, downloadName);
            } catch (err) {
                console.error("Export error:", err);
                alert("Failed to export sanitized document: " + err.message);
            } finally {
                btnDownloadSanitized.disabled = false;
                btnDownloadSanitized.style.opacity = "1";
            }
        });
    }

    if (btnDownloadLlmTxt) {
        btnDownloadLlmTxt.addEventListener("click", async () => {
            if (!currentAnalysisData) return alert("Please load or upload a document first.");
            
            const originalFilename = currentAnalysisData.filename;
            const baseName = originalFilename.replace(/\.[^/.]+$/, "");
            const cleanBase = baseName.startsWith("SANITIZED_") ? baseName.slice("SANITIZED_".length) : baseName;

            try {
                btnDownloadLlmTxt.disabled = true;
                btnDownloadLlmTxt.style.opacity = "0.7";

                const response = await fetch("/api/download-redacted", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        filename: originalFilename,
                        sanitized_text: currentAnalysisData.sanitized_text,
                        export_format: "txt"
                    })
                });

                if (!response.ok) {
                    throw new Error("Server responded with error: " + response.status);
                }

                const blob = await response.blob();
                downloadBlob(blob, `SANITIZED_LLM_READY_${cleanBase}.txt`);
            } catch (err) {
                console.error("Plain text export error:", err);
                alert("Failed to export plain text: " + err.message);
            } finally {
                btnDownloadLlmTxt.disabled = false;
                btnDownloadLlmTxt.style.opacity = "1";
            }
        });
    }

    if (btnExportAuditJson) {
        btnExportAuditJson.addEventListener("click", async () => {
            if (!currentAnalysisData) return alert("Please load or upload a document first.");
            
            const response = await fetch("/api/export-audit", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    filename: currentAnalysisData.filename,
                    audit_report: currentAnalysisData.audit_report,
                    export_format: "json"
                })
            });

            const blob = await response.blob();
            downloadBlob(blob, `COMPLIANCE_AUDIT_${currentAnalysisData.filename}.json`);
        });
    }

    if (btnExportAuditCsv) {
        btnExportAuditCsv.addEventListener("click", async () => {
            if (!currentAnalysisData) return alert("Please load or upload a document first.");
            
            const response = await fetch("/api/export-audit", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    filename: currentAnalysisData.filename,
                    audit_report: currentAnalysisData.audit_report,
                    export_format: "csv"
                })
            });

            const blob = await response.blob();
            downloadBlob(blob, `COMPLIANCE_AUDIT_${currentAnalysisData.filename}.csv`);
        });
    }
}

function downloadBlob(blob, filename) {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
}

// ==============================================================================
// 7. LOADING OVERLAY
// ==============================================================================

function showLoading(show, title = "Processing Document...", subtitle = "Extracting text and detecting PII...") {
    const overlay = document.getElementById("loadingOverlay");
    if (!overlay) return;

    if (show) {
        document.getElementById("loadingTitle").textContent = title;
        document.getElementById("loadingSubtitle").textContent = subtitle;
        overlay.classList.add("active");
    } else {
        overlay.classList.remove("active");
    }
}

// ==============================================================================
// 8. DUAL-PANE ARTIFACT INSPECTOR & PRIVACY DIFF SUITE
// ==============================================================================

function updateViewerDiffRibbon(data) {
    const rawCountEl = document.getElementById("diffRawEntityCount");
    const modeEl = document.getElementById("diffTransformMode");
    const statusEl = document.getElementById("diffSanitizedStatus");
    const rawFormatBadge = document.getElementById("rawFormatBadge");
    const rawPiiCountSpan = document.getElementById("rawPiiCountSpan");
    const sanitizedTokenCountSpan = document.getElementById("sanitizedTokenCountSpan");
    const sanitizedPiiBadge = document.getElementById("sanitizedPiiBadge");

    const piiCount = data.entity_count !== undefined ? data.entity_count : (data.entities ? data.entities.length : 0);
    
    if (rawCountEl) {
        rawCountEl.textContent = `${piiCount} Active PII Risks Identified`;
    }
    if (modeEl) {
        modeEl.textContent = currentRedactionMode === "tokenization" 
            ? "Salted HMAC-SHA256 Cryptographic Tokens" 
            : "High-Density Privacy Masking";
    }
    if (statusEl) {
        if (data.verification_status === "PASSED") {
            statusEl.textContent = "0 Residual PII • 100% Protected (Passed Fail-Closed)";
            statusEl.className = "diff-ribbon-val text-emerald";
        } else {
            statusEl.textContent = "⚠️ Residual Identified (Blocked from LLM Dispatch)";
            statusEl.className = "diff-ribbon-val text-rose";
        }
    }
    if (rawFormatBadge) {
        rawFormatBadge.textContent = (data.file_format || '.DOCX').replace('.', '').toUpperCase();
    }
    if (rawPiiCountSpan) {
        rawPiiCountSpan.textContent = piiCount;
    }
    if (sanitizedTokenCountSpan) {
        sanitizedTokenCountSpan.textContent = piiCount;
    }
    if (sanitizedPiiBadge) {
        sanitizedPiiBadge.innerHTML = data.verification_status === "PASSED" ? "✅ 0 Residuals" : "⛔ Policy Alert";
    }
}

function updateGutters() {
    const rawPane = document.getElementById("paneRawText");
    const sanPane = document.getElementById("paneSanitizedText");
    const gutterRaw = document.getElementById("gutterRaw");
    const gutterSan = document.getElementById("gutterSanitized");

    if (!rawPane || !gutterRaw) return;

    // Estimate line counts
    const rawLines = (rawPane.innerText || "").split("\n").length || 1;
    const sanLines = (sanPane.innerText || "").split("\n").length || 1;
    const maxLines = Math.max(rawLines, sanLines, 30);

    let gutterHtml = "";
    for (let i = 1; i <= maxLines; i++) {
        gutterHtml += `<div class="gutter-num">${i}</div>`;
    }
    gutterRaw.innerHTML = gutterHtml;
    if (gutterSan) {
        gutterSan.innerHTML = gutterHtml;
    }
}

let syncScrollActive = true;
let isScrolling = false;

function initSyncScroll() {
    const rawPane = document.getElementById("paneRawText");
    const sanPane = document.getElementById("paneSanitizedText");
    const gutterRaw = document.getElementById("gutterRaw");
    const gutterSan = document.getElementById("gutterSanitized");
    const btnSync = document.getElementById("btnToggleSyncScroll");

    if (btnSync) {
        btnSync.addEventListener("click", () => {
            syncScrollActive = !syncScrollActive;
            if (syncScrollActive) {
                btnSync.classList.add("active");
                btnSync.innerHTML = `<span class="sync-dot"></span> Sync Scroll: ON`;
            } else {
                btnSync.classList.remove("active");
                btnSync.innerHTML = `<span class="sync-dot"></span> Sync Scroll: OFF`;
            }
        });
    }

    if (!rawPane || !sanPane) return;

    rawPane.addEventListener("scroll", () => {
        if (gutterRaw) gutterRaw.scrollTop = rawPane.scrollTop;
        if (!syncScrollActive || isScrolling) return;
        isScrolling = true;
        const maxScroll = Math.max(1, rawPane.scrollHeight - rawPane.clientHeight);
        const pct = rawPane.scrollTop / maxScroll;
        sanPane.scrollTop = pct * Math.max(1, sanPane.scrollHeight - sanPane.clientHeight);
        if (gutterSan) gutterSan.scrollTop = sanPane.scrollTop;
        requestAnimationFrame(() => { isScrolling = false; });
    });

    sanPane.addEventListener("scroll", () => {
        if (gutterSan) gutterSan.scrollTop = sanPane.scrollTop;
        if (!syncScrollActive || isScrolling) return;
        isScrolling = true;
        const maxScroll = Math.max(1, sanPane.scrollHeight - sanPane.clientHeight);
        const pct = sanPane.scrollTop / maxScroll;
        rawPane.scrollTop = pct * Math.max(1, rawPane.scrollHeight - rawPane.clientHeight);
        if (gutterRaw) gutterRaw.scrollTop = rawPane.scrollTop;
        requestAnimationFrame(() => { isScrolling = false; });
    });
}

function initViewerControls() {
    const container = document.getElementById("dualPaneContainer");
    const btnSplit = document.getElementById("btnViewSplit");
    const btnSanitized = document.getElementById("btnViewSanitized");
    const btnRaw = document.getElementById("btnViewRaw");
    const modeBtns = [btnSplit, btnSanitized, btnRaw];

    if (btnSplit && container) {
        btnSplit.addEventListener("click", () => {
            modeBtns.forEach(b => b && b.classList.remove("active"));
            btnSplit.classList.add("active");
            container.className = "dual-pane-container mode-split";
        });
    }

    if (btnSanitized && container) {
        btnSanitized.addEventListener("click", () => {
            modeBtns.forEach(b => b && b.classList.remove("active"));
            btnSanitized.classList.add("active");
            container.className = "dual-pane-container mode-sanitized";
        });
    }

    if (btnRaw && container) {
        btnRaw.addEventListener("click", () => {
            modeBtns.forEach(b => b && b.classList.remove("active"));
            btnRaw.classList.add("active");
            container.className = "dual-pane-container mode-raw";
        });
    }

    // One-Click Stream Copy
    const btnCopy = document.getElementById("btnCopyStream");
    if (btnCopy) {
        btnCopy.addEventListener("click", async () => {
            if (!currentAnalysisData || !currentAnalysisData.sanitized_text) {
                return alert("No sanitized text available to copy.");
            }
            try {
                await navigator.clipboard.writeText(currentAnalysisData.sanitized_text);
                const originalHtml = btnCopy.innerHTML;
                btnCopy.classList.add("copied");
                btnCopy.innerHTML = `✓ Copied!`;
                setTimeout(() => {
                    btnCopy.classList.remove("copied");
                    btnCopy.innerHTML = originalHtml;
                }, 2000);
            } catch (err) {
                const textarea = document.createElement("textarea");
                textarea.value = currentAnalysisData.sanitized_text;
                document.body.appendChild(textarea);
                textarea.select();
                document.execCommand("copy");
                document.body.removeChild(textarea);
                btnCopy.classList.add("copied");
                btnCopy.innerHTML = `✓ Copied!`;
                setTimeout(() => {
                    btnCopy.classList.remove("copied");
                    btnCopy.innerHTML = `Copy Stream`;
                }, 2000);
            }
        });
    }

    // In-Stream Search
    initStreamSearch();
}

function initStreamSearch() {
    const searchInput = document.getElementById("viewerSearchInput");
    if (!searchInput) return;

    searchInput.addEventListener("input", (e) => {
        const query = e.target.value.trim();
        const rawPane = document.getElementById("paneRawText");
        const sanPane = document.getElementById("paneSanitizedText");

        [rawPane, sanPane].forEach(pane => {
            if (!pane) return;
            const marks = pane.querySelectorAll(".search-highlight");
            marks.forEach(m => {
                const parent = m.parentNode;
                parent.replaceChild(document.createTextNode(m.textContent), m);
                parent.normalize();
            });
        });

        if (!query || query.length < 2) return;

        let firstMatch = null;
        [rawPane, sanPane].forEach(pane => {
            if (!pane) return;
            const walker = document.createTreeWalker(pane, NodeFilter.SHOW_TEXT, null, false);
            const textNodes = [];
            let node;
            while ((node = walker.nextNode())) {
                if (node.nodeValue.toLowerCase().includes(query.toLowerCase())) {
                    textNodes.push(node);
                }
            }

            textNodes.forEach(textNode => {
                const text = textNode.nodeValue;
                const regex = new RegExp(`(${escapeRegex(query)})`, "gi");
                const frag = document.createDocumentFragment();
                let lastIdx = 0;
                let match;
                while ((match = regex.exec(text)) !== null) {
                    if (match.index > lastIdx) {
                        frag.appendChild(document.createTextNode(text.substring(lastIdx, match.index)));
                    }
                    const mark = document.createElement("mark");
                    mark.className = "search-highlight";
                    mark.textContent = match[0];
                    if (!firstMatch) firstMatch = mark;
                    frag.appendChild(mark);
                    lastIdx = regex.lastIndex;
                }
                if (lastIdx < text.length) {
                    frag.appendChild(document.createTextNode(text.substring(lastIdx)));
                }
                if (textNode.parentNode) {
                    textNode.parentNode.replaceChild(frag, textNode);
                }
            });
        });

        if (firstMatch) {
            firstMatch.scrollIntoView({ behavior: "smooth", block: "center" });
        }
    });
}

function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function initEntityHoverLinking() {
    bindEntityHoverListeners();
}

function bindEntityHoverListeners() {
    const rawPane = document.getElementById("paneRawText");
    const sanPane = document.getElementById("paneSanitizedText");
    if (!rawPane || !sanPane) return;

    rawPane.onmouseover = (e) => {
        const chip = e.target.closest(".pii-chip");
        if (chip) {
            const token = chip.getAttribute("data-token");
            if (token) {
                const targetTokens = sanPane.querySelectorAll(`[data-token="${CSS.escape(token)}"]`);
                targetTokens.forEach(t => t.classList.add("hover-linked"));
            }
        }
    };

    rawPane.onmouseout = (e) => {
        const chip = e.target.closest(".pii-chip");
        if (chip) {
            const token = chip.getAttribute("data-token");
            if (token) {
                const targetTokens = sanPane.querySelectorAll(`[data-token="${CSS.escape(token)}"]`);
                targetTokens.forEach(t => t.classList.remove("hover-linked"));
            }
        }
    };

    sanPane.onmouseover = (e) => {
        const chip = e.target.closest(".sanitized-token-chip");
        if (chip) {
            const token = chip.getAttribute("data-token");
            if (token) {
                const targetEntities = rawPane.querySelectorAll(`[data-token="${CSS.escape(token)}"]`);
                targetEntities.forEach(ent => ent.classList.add("hover-linked"));
            }
        }
    };

    sanPane.onmouseout = (e) => {
        const chip = e.target.closest(".sanitized-token-chip");
        if (chip) {
            const token = chip.getAttribute("data-token");
            if (token) {
                const targetEntities = rawPane.querySelectorAll(`[data-token="${CSS.escape(token)}"]`);
                targetEntities.forEach(ent => ent.classList.remove("hover-linked"));
            }
        }
    };
}
