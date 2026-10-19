/**
 * CyberGuard Hub — Advanced Digital Safety Workspace Frontend Engine
 * Complete client-side investigation, threat metering, and evidence dossier controller.
 */

'use strict';

const STORAGE_KEY = 'cyberguard.history.v2';

const TOOL_META = {
  triage: {
    id: 'triage',
    name: 'Smart Triage',
    kicker: 'CORRELATED THREAT INVESTIGATION',
    title: 'Correlate Signals,<br><em>Understand the Full Picture.</em>',
    description: 'Inspect messages and embedded hyperlinks in tandem to detect synchronized social-engineering hooks.',
    input: 'Input Message & Embedded Links',
    button: 'Run Smart Triage',
    endpoint: '/api/analyze/triage',
    field: 'content',
    placeholder: 'Paste the full suspicious message, SMS, WhatsApp chat, or email content here...'
  },
  text: {
    id: 'text',
    name: 'Scam Message Analyzer',
    kicker: 'SOCIAL ENGINEERING INSPECTION',
    title: 'Analyze Language Hooks,<br><em>Before You Respond.</em>',
    description: 'Find urgency tactics, credential theft, payment lures, and impersonation cues across English, Hindi, and Gujarati.',
    input: 'Input Message Content',
    button: 'Analyze Message',
    endpoint: '/api/analyze/text',
    field: 'text',
    placeholder: 'Paste the message text here to scan for urgency, impersonation, or financial hooks...'
  },
  url: {
    id: 'url',
    name: 'Phishing Link Scanner',
    kicker: 'OFFLINE DESTINATION AUDIT',
    title: 'Inspect the Destination,<br><em>Without Visiting It.</em>',
    description: 'Evaluate structural URL patterns, punycode, lookalike brands, deceptive subdomains, and suspicious TLDs safely.',
    input: 'Input Target URL',
    button: 'Scan Link Safely',
    endpoint: '/api/analyze/url',
    field: 'url',
    placeholder: 'example-verify-login.account-check.xyz/auth'
  },
  code: {
    id: 'code',
    name: 'Source Code Auditor',
    kicker: 'STATIC CODE RISK ANALYSIS',
    title: 'Spot Dangerous Sinks,<br><em>With Line-Level Fixes.</em>',
    description: 'Check source code for SQL injection, command execution, hardcoded keys, deserialization, and Solidity reentrancy.',
    input: 'Input Source Code',
    button: 'Audit Code',
    endpoint: '/api/analyze/code',
    field: 'code',
    placeholder: 'Paste source code snippet here to check for common vulnerability patterns...'
  },
  media: {
    id: 'media',
    name: 'Media & EXIF Verification',
    kicker: 'FORENSIC FILE INSPECTION',
    title: 'Inspect Metadata & Signatures,<br><em>Understand File Integrity.</em>',
    description: 'Inspect magic-byte MIME mismatches, metadata tampering, EXIF properties, and SHA-256 signatures.',
    input: 'Upload Media File',
    button: 'Verify File',
    endpoint: '/api/analyze/media'
  }
};

// Attack Vector Presets for realistic testing
const PRESETS = {
  triage: [
    {
      title: 'Bank KYC Freeze & Phishing Link',
      desc: 'Simulates high-pressure bank account suspension with credential harvester link',
      value: 'URGENT: Your SBI account has been suspended due to pending KYC verification. Update your PAN immediately at https://sbi.bank-portal.verify.xyz/login to avoid permanent block. Share OTP to confirm refund.'
    },
    {
      title: 'Electricity Bill Disconnection Threat',
      desc: 'Simulates power disconnection threat common in messaging scams',
      value: 'Dear Consumer, Your electricity power will be disconnected tonight at 9:30 PM from the power station because your previous month bill was not updated. Please immediately call support or verify at http://192.168.1.100/bill-pay'
    },
    {
      title: 'Benign Calendar Invitation',
      desc: 'Low-signal baseline control message',
      value: 'Hi Manthan, lets catch up on the project status tomorrow at 3 PM over Google Meet. Looking forward to your demo.'
    }
  ],
  text: [
    {
      title: 'Hindi Electricity Disconnection Threat',
      desc: 'Regional Hindi threat pattern targeting utility consumers',
      value: 'प्रिय उपभोक्ता, आपका बिजली बिल अपडेट नहीं हुआ है, इसलिए आज रात 9:30 बजे बिजली काट दी जाएगी। तुरंत अपना बिल भुगतान करें और अपना सत्यापन कोड हमारे अधिकारी को दें।'
    },
    {
      title: 'Gujarati Bank Account Suspension',
      desc: 'Regional Gujarati bank KYC urgency and OTP lure',
      value: 'તાત્કાલિક સૂચના: તમારું બેંક એકાઉન્ટ સુરક્ષા કારણોસર બ્લોક કરવામાં આવ્યું છે. તરત જ ચાલુ કરવા માટે તમારો ઓટીપી અને પાસવર્ડ દાખલ કરો.'
    },
    {
      title: 'Work-From-Home Telegram Task Scam',
      desc: 'High-yield investment and daily task employment hook',
      value: 'Special Job Offer: Earn 5000 per day with simple work from home YouTube like tasks. No experience needed. Contact our Telegram task manager immediately for your bonus payment.'
    },
    {
      title: 'Unsolicited Lottery / Gift Card Lure',
      desc: 'Classic cash refund or prize winner lure',
      value: 'CONGRATULATIONS! You have won a $10,000 cash prize in our festival lucky draw. Click here to claim your cashback refund before expiration.'
    }
  ],
  url: [
    {
      title: 'Typosquatting PayPal Lookalike',
      desc: 'Levenshtein 1-edit distance brand impersonation',
      value: 'https://paypa1.com/verify-account/login'
    },
    {
      title: 'Raw IP Credential Harvester',
      desc: 'Numeric destination concealing server origin',
      value: 'http://192.168.1.100/secure/banking/auth'
    },
    {
      title: 'Brand Subdomain on Disposable TLD',
      desc: 'Major bank name embedded in deep subdomain on .xyz',
      value: 'http://sbi.account-security.customer-service.xyz/login'
    },
    {
      title: 'Punycode IDN Homograph Lookalike',
      desc: 'Unicode character substitution resembling brand domain',
      value: 'https://xn--pple-43d.com/support/login'
    }
  ],
  code: [
    {
      title: 'Python SQL Injection & Leaked API Secret',
      desc: 'Concatenated SQL string query and exposed secret key',
      value: 'import os, subprocess\n\ndef get_user(email):\n    query = "SELECT * FROM users WHERE email = \'" + email + "\'"\n    cursor.execute(query)\n    API_KEY = "sk_live_9948271638472910"\n    subprocess.run("ping -c 1 " + email, shell=True)\n    return cursor.fetchall()'
    },
    {
      title: 'Solidity Reentrancy & tx.origin Auth',
      desc: 'State update after external call and improper authorization',
      value: 'contract VulnerableVault {\n    mapping(address => uint256) public balances;\n\n    function withdraw(uint256 amount) public {\n        require(tx.origin == msg.sender, "Unauthorized");\n        require(balances[msg.sender] >= amount);\n        (bool sent, ) = msg.sender.call{value: amount}("");\n        require(sent, "Failed to send Ether");\n        balances[msg.sender] -= amount;\n    }\n}'
    },
    {
      title: 'JavaScript DOM XSS & Dynamic Execution',
      desc: 'Unsafe innerHTML sink and eval call',
      value: 'function renderProfile(userProfile) {\n    document.getElementById("profile").innerHTML = userProfile.bio;\n    const parsedSettings = eval("(" + userProfile.settings + ")");\n    return parsedSettings;\n}'
    },
    {
      title: 'Insecure Deserialization & Disabled TLS',
      desc: 'Python pickle loading untrusted bytes with TLS verification off',
      value: 'import pickle, requests\n\ndef fetch_remote_state(url):\n    res = requests.get(url, verify=False)\n    state = pickle.loads(res.content)\n    return state'
    }
  ],
  media: []
};

// Utilities
const $ = selector => document.querySelector(selector);
const $$ = selector => document.querySelectorAll(selector);

let currentTool = 'triage';
let currentReport = null;
let toastTimeout = null;
let allRulesCache = [];

function escapeHtml(val) {
  return String(val ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function showToast(message, isError = false) {
  const toast = $('#toast');
  const icon = $('#toast-icon');
  const msg = $('#toast-message');

  icon.textContent = isError ? '✕' : '✓';
  msg.textContent = message;
  toast.style.borderColor = isError ? 'rgba(239, 68, 68, 0.5)' : 'rgba(16, 185, 129, 0.4)';
  toast.style.background = isError ? '#2d1518' : '#0f2b23';
  toast.style.color = isError ? '#fca5a5' : '#a7f3d0';

  toast.classList.add('show');
  clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => toast.classList.remove('show'), 3500);
}

// Local Storage Audit Repository
function getHistory() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
  } catch {
    return [];
  }
}

function saveHistoryEntry(entry) {
  try {
    const list = [entry, ...getHistory().slice(0, 49)];
    localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
    updateStatsAndCounts();
  } catch {
    showToast('Storage capacity reached. Clear older reports.', true);
  }
}

function deleteHistoryEntry(id) {
  try {
    const list = getHistory().filter(item => item.id !== id);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
    renderHistoryPage();
    renderDashboardRecent();
    updateStatsAndCounts();
    showToast('Investigation removed from audit log.');
  } catch (e) {
    showToast(e.message, true);
  }
}

// Page Navigation
function showPage(pageId) {
  const isTool = Object.hasOwn(TOOL_META, pageId);
  const targetPage = isTool ? 'investigate' : pageId;

  $$('.page-view').forEach(p => p.classList.toggle('active-page', p.id === `page-${targetPage}`));
  $$('.nav-link').forEach(link => link.classList.toggle('active', link.dataset.page === pageId));

  // Update Breadcrumbs
  const breadcrumb = $('#breadcrumb-current');
  if (isTool) {
    breadcrumb.textContent = TOOL_META[pageId].name;
    selectTool(pageId);
  } else {
    breadcrumb.textContent = {
      dashboard: 'Overview',
      playbooks: 'Incident Playbooks',
      rules: 'Rules Catalog',
      history: 'Audit History'
    }[pageId] || 'Workspace';
  }

  // Close mobile sidebar if open
  closeMobileSidebar();

  window.scrollTo({ top: 0, behavior: 'smooth' });

  if (pageId === 'dashboard') {
    renderDashboardRecent();
    updateStatsAndCounts();
  } else if (pageId === 'history') {
    renderHistoryPage();
  } else if (pageId === 'rules') {
    loadRulesCatalog();
  }
}

// Tool Tab Selection
function selectTool(toolKey) {
  currentTool = toolKey;
  const meta = TOOL_META[toolKey];

  $$('.module-tab').forEach(tab => tab.classList.toggle('active', tab.dataset.tool === toolKey));
  $$('.form-module').forEach(f => f.classList.add('hidden'));

  const formElement = $(`#form-${toolKey}`);
  if (formElement) formElement.classList.remove('hidden');

  $('#tool-overline').textContent = meta.kicker;
  $('#tool-title').innerHTML = meta.title;
  $('#tool-description').textContent = meta.description;
  $('#input-heading').textContent = meta.input;
  $('#analyze-label').textContent = meta.button;

  // Clear report panel state
  $('#report-placeholder').classList.remove('hidden');
  $('#report-output').classList.add('hidden');
  $('#report-actions').classList.add('hidden');
  setReportState('ready', 'AWAITING INPUT');
  currentReport = null;
}

function setReportState(state, text) {
  const badge = $('#report-state');
  const label = $('#report-state-label');
  badge.className = `report-state-pill state-${state}`;
  label.textContent = text;
}

// Setup Event Listeners
function setupEvents() {
  // Navigation Links
  $$('[data-page]').forEach(el => el.addEventListener('click', () => showPage(el.dataset.page)));
  $$('[data-go]').forEach(el => el.addEventListener('click', () => showPage(el.dataset.go)));
  $$('[data-tool]').forEach(el => el.addEventListener('click', () => selectTool(el.dataset.tool)));

  // Mobile Sidebar Toggle
  $('#mobile-menu-toggle')?.addEventListener('click', openMobileSidebar);
  $('#mobile-sidebar-close')?.addEventListener('click', closeMobileSidebar);
  $('#sidebar-overlay')?.addEventListener('click', closeMobileSidebar);

  // Topbar Actions
  $('#quick-playbooks-btn')?.addEventListener('click', () => showPage('playbooks'));
  $('#sidebar-privacy-btn')?.addEventListener('click', openPrivacyDialog);
  $('#privacy-info-btn')?.addEventListener('click', openPrivacyDialog);
  $('#dashboard-privacy-learn')?.addEventListener('click', openPrivacyDialog);
  $('#close-privacy-dialog')?.addEventListener('click', closePrivacyDialog);
  $('#privacy-dialog-ok')?.addEventListener('click', closePrivacyDialog);

  // Fallback light-dismiss for browsers lacking closedby support
  setupDialogFallback($('#privacy-dialog'));
  setupDialogFallback($('#preset-dialog'));

  // Attack Vector Presets Dialog
  $('#sample-trigger-btn')?.addEventListener('click', openPresetDialog);
  $('#close-preset-dialog')?.addEventListener('click', closePresetDialog);

  // Media Dropzone Events
  setupMediaDropzone();

  // Character Counters
  setupCharCounters();

  // Analysis Button
  $('#analyze-button')?.addEventListener('click', runAnalysis);

  // Keyboard shortcut: Cmd/Ctrl + Enter to trigger analysis
  document.addEventListener('keydown', e => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      const activePage = $('.page-view.active-page');
      if (activePage && activePage.id === 'page-investigate') {
        e.preventDefault();
        runAnalysis();
      }
    }
  });

  // Report Export Actions
  $('#copy-report')?.addEventListener('click', copyReportSummary);
  $('#download-report')?.addEventListener('click', exportReportJSON);
  $('#download-md-report')?.addEventListener('click', exportReportMarkdown);
  $('#print-report')?.addEventListener('click', () => window.print());

  // History Actions
  $('#history-search')?.addEventListener('input', renderHistoryPage);
  $('#history-filter')?.addEventListener('change', renderHistoryPage);
  $('#clear-history')?.addEventListener('click', clearAllHistory);

  // Rules Catalog Actions
  $('#rules-search')?.addEventListener('input', filterRulesCatalog);
  $$('#rules-filter-pills .filter-pill').forEach(btn => {
    btn.addEventListener('click', () => {
      $$('#rules-filter-pills .filter-pill').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      filterRulesCatalog();
    });
  });
}

function openMobileSidebar() {
  $('#app-sidebar').classList.add('mobile-open');
  $('#sidebar-overlay').classList.add('mobile-open');
}

function closeMobileSidebar() {
  $('#app-sidebar').classList.remove('mobile-open');
  $('#sidebar-overlay').classList.remove('mobile-open');
}

function openPrivacyDialog() {
  const dialog = $('#privacy-dialog');
  if (dialog?.showModal) dialog.showModal();
}

function closePrivacyDialog() {
  const dialog = $('#privacy-dialog');
  if (dialog?.close) dialog.close();
}

function openPresetDialog() {
  const dialog = $('#preset-dialog');
  const container = $('#preset-items-list');
  const presets = PRESETS[currentTool] || [];

  if (!presets.length) {
    showToast('Presets are not applicable for file upload. Choose a sample file from your system.');
    return;
  }

  container.innerHTML = presets.map((preset, idx) => `
    <button class="preset-option-btn" data-preset-idx="${idx}">
      <div>
        <div class="preset-option-title">${escapeHtml(preset.title)}</div>
        <div class="preset-option-desc">${escapeHtml(preset.desc)}</div>
      </div>
      <span class="text-sub">Select →</span>
    </button>
  `).join('');

  container.querySelectorAll('[data-preset-idx]').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = parseInt(btn.dataset.presetIdx, 10);
      loadPresetValue(presets[idx].value);
      closePresetDialog();
    });
  });

  if (dialog?.showModal) dialog.showModal();
}

function closePresetDialog() {
  const dialog = $('#preset-dialog');
  if (dialog?.close) dialog.close();
}

function loadPresetValue(val) {
  if (currentTool === 'triage') {
    $('#triage-input').value = val;
    $('#triage-counter').textContent = `${val.length} chars`;
  } else if (currentTool === 'text') {
    $('#text-input').value = val;
    $('#text-counter').textContent = `${val.length} chars`;
  } else if (currentTool === 'url') {
    $('#url-input').value = val.replace(/^https?:\/\//i, '');
  } else if (currentTool === 'code') {
    $('#code-input').value = val;
    $('#code-counter').textContent = `${val.length} chars`;
  }
  showToast('Preset loaded into input panel.');
}

/**
 * Modern Web Guidance: Fallback light-dismiss for browsers lacking closedby support
 */
function setupDialogFallback(dialog) {
  if (!dialog) return;
  if (!('closedBy' in HTMLDialogElement.prototype)) {
    dialog.addEventListener('click', event => {
      if (event.target !== dialog) return;
      const rect = dialog.getBoundingClientRect();
      const isInside = (
        rect.top <= event.clientY &&
        event.clientY <= rect.top + rect.height &&
        rect.left <= event.clientX &&
        event.clientX <= rect.left + rect.width
      );
      if (!isInside) dialog.close();
    });
  }
}

// Media Dropzone Setup
function setupMediaDropzone() {
  const dropZone = $('#media-drop-zone');
  const fileInput = $('#media-input');
  const previewBox = $('#preview-media-box');
  const previewContainer = $('#media-preview-container');
  const previewName = $('#preview-filename');
  const previewSize = $('#preview-filesize');
  const clearBtn = $('#clear-media-btn');

  dropZone?.addEventListener('click', () => fileInput.click());

  dropZone?.addEventListener('dragover', e => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });

  dropZone?.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));

  dropZone?.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files?.length) {
      fileInput.files = e.dataTransfer.files;
      handleFileSelected(fileInput.files[0]);
    }
  });

  fileInput?.addEventListener('change', () => {
    if (fileInput.files?.length) {
      handleFileSelected(fileInput.files[0]);
    }
  });

  clearBtn?.addEventListener('click', e => {
    e.stopPropagation();
    fileInput.value = '';
    previewContainer.classList.add('hidden');
    dropZone.classList.remove('hidden');
    $('#file-label').textContent = 'Click or Drag & Drop File';
  });

  function handleFileSelected(file) {
    if (!file) return;
    previewName.textContent = file.name;
    previewSize.textContent = `${(file.size / 1024).toFixed(1)} KB`;
    $('#file-label').textContent = file.name;

    previewBox.innerHTML = '';
    if (file.type.startsWith('image/')) {
      const img = document.createElement('img');
      img.src = URL.createObjectURL(file);
      previewBox.appendChild(img);
    } else if (file.type.startsWith('audio/')) {
      previewBox.innerHTML = `<svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18V5l12-2v13"></path><circle cx="6" cy="18" r="3"></circle><circle cx="18" cy="16" r="3"></circle></svg>`;
    } else if (file.type.startsWith('video/')) {
      previewBox.innerHTML = `<svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2"><polygon points="23 7 16 12 23 17 23 7"></polygon><rect x="1" y="5" width="15" height="14" rx="2" ry="2"></rect></svg>`;
    }

    dropZone.classList.add('hidden');
    previewContainer.classList.remove('hidden');
  }
}

function setupCharCounters() {
  $('#triage-input')?.addEventListener('input', e => {
    $('#triage-counter').textContent = `${e.target.value.length} chars`;
  });
  $('#text-input')?.addEventListener('input', e => {
    $('#text-counter').textContent = `${e.target.value.length} chars`;
  });
  $('#code-input')?.addEventListener('input', e => {
    $('#code-counter').textContent = `${e.target.value.length} chars`;
  });
}

// --------------------------------------------------------------------------
// Core Analysis Execution
// --------------------------------------------------------------------------
async function runAnalysis() {
  const btn = $('#analyze-button');
  const label = $('#analyze-label');
  const meta = TOOL_META[currentTool];

  btn.disabled = true;
  label.textContent = 'Executing Heuristics...';
  setReportState('working', 'ANALYZING');

  $('#report-placeholder').classList.add('hidden');
  $('#report-actions').classList.add('hidden');
  const output = $('#report-output');
  output.classList.remove('hidden');
  output.innerHTML = `
    <div class="report-empty-state">
      <div class="empty-icon-orbit">
        <svg viewBox="0 0 24 24" width="36" height="36" fill="none" stroke="currentColor" stroke-width="2" class="pulse-beacon">
          <circle cx="12" cy="12" r="10"></circle>
          <polyline points="12 6 12 12 16 14"></polyline>
        </svg>
      </div>
      <h3 class="empty-title">Auditing Signals...</h3>
      <p class="empty-desc">Evaluating pattern heuristics, domain characteristics, and structural indicators.</p>
    </div>
  `;

  try {
    let response;
    let submittedContent = '';

    if (currentTool === 'media') {
      const file = $('#media-input').files[0];
      if (!file) throw new Error('Please select an image, audio, or video file to inspect.');

      const form = new FormData();
      form.append('file', file);
      form.append('ai_visual_review', $('#media-ai-consent').checked ? 'true' : 'false');
      response = await fetch(meta.endpoint, { method: 'POST', body: form });
    } else {
      const inputMap = { triage: 'triage-input', text: 'text-input', url: 'url-input', code: 'code-input' };
      const rawInput = $('#' + inputMap[currentTool]).value.trim();

      if (rawInput.length < 3) {
        throw new Error('Please enter at least 3 characters of content before auditing.');
      }

      submittedContent = rawInput;
      response = await fetch(meta.endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [meta.field]: rawInput })
      });
    }

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.detail || 'The security evaluation could not be completed.');
    }

    currentReport = data;
    renderEvidenceReport(data, submittedContent);
    saveAuditRecord(currentTool, data, submittedContent);
    setReportState('complete', 'REPORT READY');
    $('#report-actions').classList.remove('hidden');
    showToast('Investigation complete. Report saved to device audit log.');
  } catch (err) {
    output.innerHTML = `
      <div class="report-empty-state">
        <div class="empty-icon-orbit" style="color: var(--red); border-color: rgba(239, 68, 68, 0.4);">
          <svg viewBox="0 0 24 24" width="36" height="36" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="8" x2="12" y2="12"></line>
            <line x1="12" y1="16" x2="12.01" y2="16"></line>
          </svg>
        </div>
        <h3 class="empty-title">Investigation Paused</h3>
        <p class="empty-desc" style="color: #fca5a5;">${escapeHtml(err.message)}</p>
      </div>
    `;
    setReportState('ready', 'NEEDS INPUT');
    showToast(err.message, true);
  } finally {
    btn.disabled = false;
    label.textContent = meta.button;
  }
}

// --------------------------------------------------------------------------
// Report Rendering & Formatting
// --------------------------------------------------------------------------
function renderEvidenceReport(data, rawInput) {
  const score = data.risk_score;
  const risk = data.risk_level || 'inconclusive';
  let html = '';

  // 1. Threat Score Banner & Circular Gauge
  const radius = 30;
  const circumference = 2 * Math.PI * radius;
  const strokeOffset = score !== undefined ? circumference - (score / 100) * circumference : circumference;
  const strokeColor = risk === 'high' ? 'var(--red)' : risk === 'medium' ? 'var(--amber)' : risk === 'low' ? 'var(--mint)' : 'var(--text-sub)';

  html += `
    <div class="threat-gauge-banner">
      <div class="gauge-circular">
        <svg class="gauge-svg" viewBox="0 0 72 72">
          <circle class="gauge-track" cx="36" cy="36" r="${radius}"></circle>
          <circle class="gauge-fill" cx="36" cy="36" r="${radius}" 
                  stroke="${strokeColor}" 
                  stroke-dasharray="${circumference}" 
                  stroke-dashoffset="${strokeOffset}"></circle>
        </svg>
        <div class="gauge-score-value">
          <b>${score !== undefined ? score : '—'}</b>
          <small>SCORE</small>
        </div>
      </div>
      <div class="gauge-verdict-col">
        <div class="verdict-header-row">
          <span class="verdict-badge risk-${escapeHtml(risk)}">${escapeHtml(risk)} threat signals</span>
          ${data.analysis_mode ? `<span class="tag-pill">${escapeHtml(data.analysis_mode)}</span>` : ''}
        </div>
        <div class="verdict-desc">
          ${score >= 55 ? 'High risk indicators detected. Treat content with caution.' : score >= 20 ? 'Elevated suspicion cues observed. Verify independently.' : 'Low configured heuristic matches. Note: absence of signals does not certify safety.'}
        </div>
      </div>
    </div>
  `;

  // 2. Summary
  if (data.summary) {
    html += `
      <div class="dossier-section">
        <div class="dossier-header-row">
          <span class="dossier-tag">EXECUTIVE SUMMARY</span>
        </div>
        <p class="dossier-summary-text">${escapeHtml(data.summary)}</p>
      </div>
    `;
  }

  // 3. Highlighted Scam Text Viewer (if text/triage findings exist)
  if ((currentTool === 'text' || currentTool === 'triage') && rawInput && data.findings?.length) {
    html += `
      <div class="dossier-section">
        <div class="dossier-header-row">
          <span class="dossier-tag">SIGNAL HIGHLIGHT VIEWER</span>
          <span class="dossier-count">${data.findings.length} cues</span>
        </div>
        <div class="highlight-text-viewer">
          ${renderHighlightedSpans(rawInput, data.findings)}
        </div>
      </div>
    `;
  }

  // 4. URL Structural Component Breakdown
  if (data.components) {
    const c = data.components;
    html += `
      <div class="dossier-section">
        <div class="dossier-header-row">
          <span class="dossier-tag">URL STRUCTURE BREAKDOWN</span>
          ${c.brand_match ? `<span class="tag-pill" style="color: var(--amber)">Matched: ${escapeHtml(c.brand_match)}</span>` : ''}
        </div>
        <div class="url-component-tree">
          <div class="url-tree-row">
            <span class="url-node url-scheme">${escapeHtml(c.scheme || 'https')}://</span>
            ${c.subdomain ? `<span class="url-node url-subdomain" title="Subdomain">${escapeHtml(c.subdomain)}</span>` : ''}
            <span class="url-node url-domain" title="Registrable Root Domain">${escapeHtml(c.domain || c.host)}</span>
            ${c.tld ? `<span class="url-node url-tld" title="Top-Level Domain">.${escapeHtml(c.tld)}</span>` : ''}
            <span class="url-node url-path" title="Path">${escapeHtml(c.path || '/')}</span>
          </div>
          ${c.query ? `<div class="url-tree-row"><span class="text-sub" style="font-size: 0.75rem">Query Params:</span><span class="url-node" style="color: var(--text-muted)">?${escapeHtml(c.query)}</span></div>` : ''}
        </div>
      </div>
    `;
  }

  // 5. Embedded Links (Smart Triage)
  if (data.url_analyses?.length) {
    html += `
      <div class="dossier-section">
        <div class="dossier-header-row">
          <span class="dossier-tag">EMBEDDED HYPERLINKS INSPECTED</span>
          <span class="dossier-count">${data.url_analyses.length} link(s)</span>
        </div>
        <div class="evidence-cards-list">
          ${data.url_analyses.map(link => `
            <div class="evidence-card sev-${escapeHtml(link.risk_level)}">
              <div class="evidence-top-row">
                <span class="evidence-category-badge">${escapeHtml(link.host)}</span>
                <span class="history-risk-pill risk-${escapeHtml(link.risk_level)}">${escapeHtml(link.risk_level)}</span>
              </div>
              <div class="evidence-snippet-box">${escapeHtml(link.url || link.host)}</div>
              <div class="evidence-why">
                ${link.findings?.length 
                  ? link.findings.map(f => typeof f === 'string' ? escapeHtml(f) : escapeHtml(f.category)).join(' · ')
                  : 'No high-risk URL patterns matched.'}
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  // 6. Observed Evidence & Findings Cards
  const findings = reportItems(data);
  if (findings.length) {
    html += `
      <div class="dossier-section">
        <div class="dossier-header-row">
          <span class="dossier-tag">OBSERVED EVIDENCE & RULES MATCHED</span>
          <span class="dossier-count">${findings.length} signal(s)</span>
        </div>
        <div class="evidence-cards-list">
          ${findings.map(item => {
            if (typeof item === 'string') {
              return `
                <div class="evidence-card sev-medium">
                  <div class="evidence-category-badge">Signal Observation</div>
                  <div class="evidence-why">${escapeHtml(item)}</div>
                </div>
              `;
            }
            const sev = item.severity || 'medium';
            const title = item.title || item.category || 'Security Indicator';
            return `
              <div class="evidence-card sev-${escapeHtml(sev)}">
                <div class="evidence-top-row">
                  <span class="evidence-category-badge">${escapeHtml(title)}</span>
                  ${item.rule_id ? `<span class="evidence-rule-id">${escapeHtml(item.rule_id)}</span>` : ''}
                </div>
                ${item.line ? `<div class="text-sub" style="font-size: 0.72rem; margin-bottom: 4px;">LINE ${escapeHtml(item.line)}</div>` : ''}
                ${item.snippet ? `<div class="evidence-snippet-box">${escapeHtml(item.snippet)}</div>` : item.evidence ? `<div class="evidence-snippet-box">${escapeHtml(item.evidence)}</div>` : ''}
                ${item.why_it_matters ? `<div class="evidence-why"><strong>Why it matters:</strong> ${escapeHtml(item.why_it_matters)}</div>` : ''}
                ${item.recommendation ? `<div class="evidence-fix"><strong>Safer next step:</strong> ${escapeHtml(item.recommendation)}</div>` : ''}
                ${item.suggested_fix ? `
                  <div class="code-fix-block">
                    <div class="code-fix-header">✓ RECOMMENDED SECURE CODE ALTERNATIVE:</div>
                    <pre class="code-fix-pre">${escapeHtml(item.suggested_fix)}</pre>
                  </div>
                ` : ''}
              </div>
            `;
          }).join('')}
        </div>
      </div>
    `;
  } else if (!data.url_analyses?.length) {
    html += `
      <div class="dossier-section">
        <div class="dossier-header-row"><span class="dossier-tag">OBSERVED EVIDENCE</span></div>
        <div class="empty-quick-hint">No configured high-signal heuristic rules matched. This does not certify that the item is safe.</div>
      </div>
    `;
  }

  // 7. Media EXIF / Forensic Metadata Table
  if (data.exif_details && Object.keys(data.exif_details).length) {
    html += `
      <div class="dossier-section">
        <div class="dossier-header-row">
          <span class="dossier-tag">EXIF FORENSIC PROPERTIES</span>
          <span class="dossier-count">${Object.keys(data.exif_details).length} tag(s)</span>
        </div>
        <table class="metadata-table">
          <thead><tr><th>ATTRIBUTE</th><th>EXTRACTED VALUE</th></tr></thead>
          <tbody>
            ${Object.entries(data.exif_details).map(([k, v]) => `
              <tr><td>${escapeHtml(k)}</td><td>${escapeHtml(v)}</td></tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  // 8. File Hash & Technical Properties
  if (data.sha256) {
    html += `
      <div class="dossier-section">
        <div class="dossier-header-row"><span class="dossier-tag">FILE INTEGRITY SIGNATURE</span></div>
        <div class="evidence-snippet-box" style="display: flex; justify-content: space-between; align-items: center;">
          <span>SHA-256: ${escapeHtml(data.sha256)}</span>
          <button class="btn-text-sub" onclick="navigator.clipboard.writeText('${escapeHtml(data.sha256)}'); showToast('Hash copied!')">Copy</button>
        </div>
        ${data.dimensions ? `<div class="text-sub" style="font-size: 0.78rem; margin-top: 4px;">Resolution: ${data.dimensions.width} × ${data.dimensions.height} px · Format: ${escapeHtml(data.format || data.content_type)} · Size: ${(data.size_bytes / 1024).toFixed(1)} KB</div>` : ''}
      </div>
    `;
  }

  // 9. AI Copilot Explanation
  if (data.ai_explanation) {
    html += `
      <div class="ai-context-card">
        <div class="ai-context-header">
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg>
          <span>${escapeHtml(data.ai_provider || 'AI')} Synthesis & Context</span>
        </div>
        <div class="ai-context-body">${escapeHtml(data.ai_explanation)}</div>
      </div>
    `;
  }

  if (data.visual_review) {
    html += `
      <div class="ai-context-card" style="border-color: rgba(6, 182, 212, 0.3);">
        <div class="ai-context-header" style="color: var(--cyan);">
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
          <span>${escapeHtml(data.visual_review.label || 'Visual Observations')}</span>
        </div>
        <div class="ai-context-body">${escapeHtml(data.visual_review.observations)}</div>
      </div>
    `;
  }

  // 10. Recommendations & Containment Next Steps
  if (data.recommendations?.length) {
    html += `
      <div class="dossier-section">
        <div class="dossier-header-row"><span class="dossier-tag">ACTIONABLE CONTAINMENT STEPS</span></div>
        <ol class="playbook-steps" style="margin-top: 6px;">
          ${data.recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
        </ol>
      </div>
    `;
  }

  // 11. Disclaimer
  if (data.disclaimer) {
    html += `
      <div class="notice-box mt-4">
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
        <span>${escapeHtml(data.disclaimer)}</span>
      </div>
    `;
  }

  $('#report-output').innerHTML = html;
}

function reportItems(data) {
  if (data.evidence?.length) return data.evidence;
  if (data.findings?.length) return data.findings;
  if (data.signals?.length) return data.signals;
  return [];
}

function renderHighlightedSpans(text, findings) {
  // Sort findings by start index
  const spans = findings
    .filter(f => f.start !== undefined && f.end !== undefined && f.start < f.end)
    .sort((a, b) => a.start - b.start);

  if (!spans.length) return escapeHtml(text);

  let result = '';
  let lastIdx = 0;

  for (const span of spans) {
    if (span.start < lastIdx) continue; // Avoid overlapping breaks
    result += escapeHtml(text.slice(lastIdx, span.start));
    result += `<mark class="scam-span" title="${escapeHtml(span.category)}: ${escapeHtml(span.why_it_matters)}">${escapeHtml(text.slice(span.start, span.end))}</mark>`;
    lastIdx = span.end;
  }
  result += escapeHtml(text.slice(lastIdx));
  return result;
}

// --------------------------------------------------------------------------
// History & Audit Logging
// --------------------------------------------------------------------------
function saveAuditRecord(tool, report, submittedSnippet) {
  const record = {
    id: crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    tool,
    toolName: TOOL_META[tool]?.name || tool,
    risk: report.risk_level || 'inconclusive',
    score: report.risk_score ?? null,
    summary: report.summary || 'Security inspection performed.',
    timestamp: new Date().toISOString(),
    findingCount: (report.findings || report.evidence || report.signals || []).length,
    snippet: (submittedSnippet || '').slice(0, 100),
    report
  };
  saveHistoryEntry(record);
}

function renderDashboardRecent() {
  const container = $('#dashboard-recent');
  if (!container) return;

  const list = getHistory().slice(0, 4);
  if (!list.length) {
    container.innerHTML = `
      <div class="empty-state-small">
        <div class="empty-state-icon">
          <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
        </div>
        <div class="empty-state-text">
          <b>No Investigations Executed Yet</b>
          <small>Launch Smart Triage with a demo preset to generate your first audit record.</small>
        </div>
        <button class="btn btn-secondary btn-sm empty-state-btn" data-go="triage">Launch Triage →</button>
      </div>
    `;
    container.querySelector('[data-go]')?.addEventListener('click', () => showPage('triage'));
    return;
  }

  container.innerHTML = list.map(item => `
    <button class="history-row-item" data-history-id="${escapeHtml(item.id)}">
      <span class="history-badge-icon risk-${escapeHtml(item.risk)}">
        ${item.risk === 'high' ? '!' : item.risk === 'medium' ? '△' : item.risk === 'low' ? '✓' : '◌'}
      </span>
      <div class="history-info">
        <b>${escapeHtml(item.toolName)}</b>
        <small>${escapeHtml(item.summary)}</small>
      </div>
      <span class="history-risk-pill risk-${escapeHtml(item.risk)}">
        ${escapeHtml(item.risk)}${item.score !== null ? ` · ${escapeHtml(item.score)}` : ''}
      </span>
      <span class="history-time">${formatDate(item.timestamp)}</span>
      <span class="history-action-arrow">↗</span>
    </button>
  `).join('');

  container.querySelectorAll('[data-history-id]').forEach(btn => {
    btn.addEventListener('click', () => loadHistoricalRecord(btn.dataset.historyId));
  });
}

function renderHistoryPage() {
  const container = $('#history-list');
  if (!container) return;

  const query = ($('#history-search')?.value || '').trim().toLowerCase();
  const filter = $('#history-filter')?.value || 'all';

  const items = getHistory().filter(item => {
    const matchesFilter = filter === 'all' || item.risk === filter;
    const matchesQuery = !query || `${item.toolName} ${item.summary} ${item.snippet}`.toLowerCase().includes(query);
    return matchesFilter && matchesQuery;
  });

  if (!items.length) {
    container.innerHTML = `
      <div class="report-empty-state">
        <div class="empty-icon-orbit">
          <svg viewBox="0 0 24 24" width="32" height="32" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
        </div>
        <h3 class="empty-title">No Audit Records Found</h3>
        <p class="empty-desc">No investigations matched your filter criteria. Run an analysis or clear your search.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = items.map(item => `
    <div class="history-card-item">
      <span class="history-badge-icon risk-${escapeHtml(item.risk)}">
        ${item.risk === 'high' ? '!' : item.risk === 'medium' ? '△' : item.risk === 'low' ? '✓' : '◌'}
      </span>
      <div class="history-card-main">
        <div class="history-card-title-row">
          <h4 class="history-card-title">${escapeHtml(item.toolName)}</h4>
          <span class="history-card-tool">${escapeHtml(item.findingCount)} signal(s)</span>
          <span class="history-risk-pill risk-${escapeHtml(item.risk)}">${escapeHtml(item.risk)}${item.score !== null ? ` · ${escapeHtml(item.score)}` : ''}</span>
        </div>
        <div class="history-card-summary">${escapeHtml(item.summary)}</div>
        <div class="history-card-date">${new Date(item.timestamp).toLocaleString()}</div>
      </div>
      <div class="history-card-actions">
        <button class="btn btn-secondary btn-sm" onclick="window.CyberGuard.loadRecord('${escapeHtml(item.id)}')">View Dossier</button>
        <button class="btn btn-danger btn-sm" onclick="window.CyberGuard.deleteRecord('${escapeHtml(item.id)}')">Delete</button>
      </div>
    </div>
  `).join('');
}

function loadHistoricalRecord(id) {
  const record = getHistory().find(r => r.id === id);
  if (!record) return;

  showPage(record.tool);
  currentReport = record.report;
  renderEvidenceReport(record.report, record.snippet);
  setReportState('complete', 'SAVED AUDIT');
  $('#report-actions').classList.remove('hidden');
  $('#report-placeholder').classList.add('hidden');
  $('#report-output').classList.remove('hidden');
}

function clearAllHistory() {
  if (!getHistory().length) {
    showToast('Audit log is already empty.');
    return;
  }
  if (confirm('Permanently purge all saved investigations from this browser?')) {
    localStorage.removeItem(STORAGE_KEY);
    renderHistoryPage();
    renderDashboardRecent();
    updateStatsAndCounts();
    showToast('Audit log cleared.');
  }
}

function updateStatsAndCounts() {
  const history = getHistory();
  const scansCount = history.length;
  const highCount = history.filter(h => h.risk === 'high').length;

  if ($('#history-count')) $('#history-count').textContent = scansCount;
  if ($('#stat-scans')) $('#stat-scans').textContent = scansCount;
  if ($('#stat-high')) $('#stat-high').textContent = highCount;
}

function formatDate(isoStr) {
  const d = new Date(isoStr);
  if (isNaN(d.getTime())) return '';
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// --------------------------------------------------------------------------
// Rules Catalog Dynamic Fetch & Search
// --------------------------------------------------------------------------
async function loadRulesCatalog() {
  if (allRulesCache.length) {
    renderRulesCatalog(allRulesCache);
    return;
  }

  const grid = $('#rules-grid');
  grid.innerHTML = '<div class="text-sub" style="padding: 24px;">Loading heuristic rules catalog...</div>';

  try {
    const res = await fetch('/api/rules');
    const data = await res.json();
    allRulesCache = data.rules || [];
    if ($('#rules-nav-count')) $('#rules-nav-count').textContent = allRulesCache.length;
    if ($('#stat-rules-count')) $('#stat-rules-count').textContent = `${allRulesCache.length}+`;
    renderRulesCatalog(allRulesCache);
  } catch {
    grid.innerHTML = '<div class="text-sub" style="padding: 24px;">Could not load rules from server.</div>';
  }
}

function filterRulesCatalog() {
  const term = ($('#rules-search')?.value || '').trim().toLowerCase();
  const activePill = $('#rules-filter-pills .filter-pill.active')?.dataset.filter || 'all';

  const filtered = allRulesCache.filter(r => {
    const matchesModule = activePill === 'all' || r.module === activePill;
    const matchesTerm = !term || `${r.rule_id} ${r.category} ${r.why_it_matters}`.toLowerCase().includes(term);
    return matchesModule && matchesTerm;
  });

  renderRulesCatalog(filtered);
}

function renderRulesCatalog(rules) {
  const grid = $('#rules-grid');
  if (!grid) return;

  if (!rules.length) {
    grid.innerHTML = '<div class="text-sub" style="padding: 24px;">No rules matched your search.</div>';
    return;
  }

  grid.innerHTML = rules.map(rule => `
    <div class="rule-catalog-card">
      <div class="rule-catalog-card-header">
        <span class="rule-id-pill">${escapeHtml(rule.rule_id)}</span>
        <span class="history-risk-pill risk-${escapeHtml(rule.severity || 'medium')}">${escapeHtml(rule.severity || 'medium')}</span>
      </div>
      <h3 class="rule-catalog-title">${escapeHtml(rule.category)}</h3>
      <div class="rule-catalog-why">${escapeHtml(rule.why_it_matters)}</div>
      <div class="rule-catalog-fix"><strong>Remediation:</strong> ${escapeHtml(rule.recommendation)}</div>
      ${rule.sample_fix ? `
        <div class="code-fix-block" style="margin-top: 8px;">
          <pre class="code-fix-pre">${escapeHtml(rule.sample_fix)}</pre>
        </div>
      ` : ''}
    </div>
  `).join('');
}

// --------------------------------------------------------------------------
// Export & Report Copying Functions
// --------------------------------------------------------------------------
function copyReportSummary() {
  if (!currentReport) return;
  const summaryText = buildReportSummaryText(currentReport);
  navigator.clipboard.writeText(summaryText)
    .then(() => showToast('Summary copied to clipboard.'))
    .catch(() => showToast('Clipboard unavailable.', true));
}

function exportReportJSON() {
  if (!currentReport) return;
  const exportPayload = {
    platform: 'CyberGuard Hub',
    module: TOOL_META[currentTool]?.name,
    exported_at: new Date().toISOString(),
    report: currentReport
  };
  const blob = new Blob([JSON.stringify(exportPayload, null, 2)], { type: 'application/json' });
  downloadBlob(blob, `cyberguard-dossier-${Date.now()}.json`);
  showToast('JSON report downloaded.');
}

function exportReportMarkdown() {
  if (!currentReport) return;
  const md = [
    `# CyberGuard Hub — Security Dossier`,
    `**Module:** ${TOOL_META[currentTool]?.name}`,
    `**Date:** ${new Date().toUTCString()}`,
    `**Threat Signal Score:** ${currentReport.risk_score ?? 'N/A'}/100 (${currentReport.risk_level?.toUpperCase() || 'INCONCLUSIVE'})`,
    ``,
    `## Executive Summary`,
    `${currentReport.summary || 'Security review completed.'}`,
    ``,
    `## Observed Evidence & Findings`,
    ...(reportItems(currentReport).map(f => {
      if (typeof f === 'string') return `- ${f}`;
      return `- **[${f.severity?.toUpperCase() || 'INFO'}] ${f.title || f.category}**: ${f.why_it_matters || ''}\n  *Recommended Fix:* ${f.recommendation || ''}`;
    })),
    ``,
    `## Containment & Next Steps`,
    ...(currentReport.recommendations?.map(r => `1. ${r}`) || []),
    ``,
    `---`,
    `*Generated locally via CyberGuard Hub. Lower scores do not certify safety.*`
  ].join('\n');

  const blob = new Blob([md], { type: 'text/markdown' });
  downloadBlob(blob, `cyberguard-dossier-${Date.now()}.md`);
  showToast('Markdown dossier downloaded.');
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function buildReportSummaryText(report) {
  return [
    `CyberGuard Hub · ${TOOL_META[currentTool]?.name || 'Security Review'}`,
    `Threat Signal Level: ${report.risk_level?.toUpperCase() || 'INCONCLUSIVE'} (${report.risk_score ?? '—'}/100)`,
    `Summary: ${report.summary || 'Analysis complete.'}`,
    '',
    'Observed Evidence:',
    ...(reportItems(report).map(item => typeof item === 'string' ? `• ${item}` : `• [${item.severity?.toUpperCase() || 'MED'}] ${item.title || item.category}: ${item.why_it_matters || ''}`)),
    '',
    'Next Steps:',
    ...(report.recommendations?.map(r => `→ ${r}`) || [])
  ].filter(Boolean).join('\n');
}

// --------------------------------------------------------------------------
// Initialization & Health Monitoring
// --------------------------------------------------------------------------
function checkHealth() {
  fetch('/health')
    .then(r => r.json())
    .then(data => {
      const statusLabel = $('#service-status');
      const modelLabel = $('#model-status');

      if (statusLabel) statusLabel.textContent = 'Ready to check';
      const limitLabel = $('#upload-limit');
      if (limitLabel && Number.isFinite(data.max_upload_mb)) limitLabel.textContent = String(data.max_upload_mb);
      if (modelLabel) {
        if (data.providers?.groq) {
          modelLabel.textContent = 'Groq key set · local fallback ready';
        } else {
          modelLabel.textContent = 'Local checks ready · no AI key';
        }
      }
    })
    .catch(() => {
      if ($('#service-status')) $('#service-status').textContent = 'Engine Offline';
      if ($('#model-status')) $('#model-status').textContent = 'Check local server';
    });
}

// Global window namespace for inline event delegates
window.CyberGuard = {
  loadRecord: loadHistoricalRecord,
  deleteRecord: deleteHistoryEntry
};

document.addEventListener('DOMContentLoaded', () => {
  setupEvents();
  renderDashboardRecent();
  updateStatsAndCounts();
  checkHealth();
  loadRulesCatalog();
});
