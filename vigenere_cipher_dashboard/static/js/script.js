/* =====================================================================
   Vigenère Cipher Dashboard — front-end logic
   Talks to the Flask API (/api/process, /api/statistics)
   ===================================================================== */

"use strict";

/* ---------- state ---------- */
let currentResult = "";
let currentMode = "encrypt";
let statsChart = null;
let highlightCells = []; // [{row, col, cell, position}]

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/* ---------- initialisation ---------- */
document.addEventListener("DOMContentLoaded", () => {
  // Respect the navigation preset (/encrypt or /decrypt)
  const preset = document.body.dataset.defaultMode;
  if (preset === "decrypt") setMode("decrypt");

  if (document.getElementById("tabulaTable")) {
    renderVigenereTable();
    renderAlphabet();
    buildChart();
    updateStatistics();
    repeatKey();

    // Live preview of the repeated key while typing
    const message = document.getElementById("messageInput");
    const key = document.getElementById("keyInput");
    if (message) message.addEventListener("input", repeatKey);
    if (key) key.addEventListener("input", repeatKey);

    // Enter (ctrl) submits
    const form = document.getElementById("cipherForm");
    if (form) {
      form.addEventListener("submit", (e) => {
        e.preventDefault();
        currentMode === "decrypt" ? decryptVigenere() : encryptVigenere();
      });
    }
  }
});

/* ---------- validation ---------- */
/**
 * Validate message + key. Returns { ok, message } — mirrors the server rules.
 */
function validateInput(message, key) {
  if (message === null || message === undefined || String(message).trim() === "") {
    return { ok: false, message: "Please enter a message." };
  }
  if (key === null || key === undefined || String(key).trim() === "") {
    return { ok: false, message: "Please enter a key." };
  }
  if (!/[a-zA-Z]/.test(key)) {
    return { ok: false, message: "Key must contain at least one alphabetic character." };
  }
  return { ok: true, message: "" };
}

function showError(text) {
  const box = document.getElementById("inputError");
  if (!box) return;
  box.textContent = text;
  box.classList.remove("d-none");
}

function clearError() {
  const box = document.getElementById("inputError");
  if (box) box.classList.add("d-none");
}

/* ---------- mode ---------- */
function setMode(mode) {
  currentMode = mode;
  const pill = document.getElementById("modePill");
  if (pill) {
    pill.textContent = mode === "encrypt" ? "Encryption" : "Decryption";
    pill.classList.toggle("dec", mode === "decrypt");
  }
  const keyInput = document.getElementById("keyInput");
  if (keyInput) {
    keyInput.placeholder = mode === "encrypt"
      ? "Enter encryption key..."
      : "Enter decryption key...";
  }
  const hint = document.getElementById("stepsHint");
  if (hint && hint.textContent.indexOf("formula") === -1) {
    hint.textContent = mode === "encrypt"
      ? "Encryption uses C = (P + K) mod 26"
      : "Decryption uses P = (C - K + 26) mod 26";
  }
}

/* ---------- key repetition (live preview) ---------- */
/**
 * Shows how the key repeats across the message.
 * Spaces / symbols do NOT consume a key character.
 */
function repeatKey() {
  const box = document.getElementById("repeatedKey");
  if (!box) return "—";

  const message = document.getElementById("messageInput").value;
  const key = document.getElementById("keyInput").value;
  const clean = key.toUpperCase().replace(/[^A-Z]/g, "");

  if (!message || !clean) {
    box.textContent = "—";
    return "—";
  }

  let repeated = "";
  let ki = 0;
  for (const ch of message) {
    const upper = ch.toUpperCase();
    if (upper >= "A" && upper <= "Z") {
      repeated += clean[ki % clean.length];
      ki++;
    } else {
      repeated += " ";
    }
  }
  box.textContent = repeated;
  return repeated;
}

/* ---------- encrypt / decrypt ---------- */
function encryptVigenere() {
  processMessage("encrypt");
}

function decryptVigenere() {
  processMessage("decrypt");
}

async function processMessage(mode) {
  const messageEl = document.getElementById("messageInput");
  const keyEl = document.getElementById("keyInput");
  const message = messageEl.value;
  const key = keyEl.value;

  clearError();

  const check = validateInput(message, key);
  if (!check.ok) {
    showError(check.message);
    (check.message.indexOf("key") > -1 ? keyEl : messageEl).focus();
    return;
  }

  setMode(mode);
  setLoading(true);

  try {
    const response = await fetch("/api/process", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode, message, key }),
    });

    const data = await response.json();

    if (!response.ok || !data.ok) {
      showError(data.error || "Something went wrong. Please try again.");
      return;
    }

    renderResult(data);
    calculateSteps(data.steps);
    applyHighlights(data.highlights);
    repeatKey();
    updateStatistics(data.statistics);
  } catch (err) {
    showError("Could not reach the server. Is Flask running?");
    console.error(err);
  } finally {
    setLoading(false);
  }
}

function setLoading(isLoading) {
  ["btnEncrypt", "btnDecrypt"].forEach((id) => {
    const btn = document.getElementById(id);
    if (btn) btn.disabled = isLoading;
  });
}

/* ---------- result card ---------- */
function renderResult(data) {
  currentResult = data.result;

  const box = document.getElementById("resultBox");
  box.textContent = data.result;
  box.classList.remove("empty");

  const badge = document.getElementById("resultBadge");
  badge.textContent = data.operation_type;
  badge.classList.remove("enc", "dec");
  badge.classList.add(data.mode === "encrypt" ? "enc" : "dec");

  document.getElementById("btnCopy").disabled = false;
  document.getElementById("btnDownload").disabled = false;
  document.getElementById("repeatedKey").textContent = data.repeated_key;
  document.getElementById("stepsHint").textContent =
    data.operation_type + " — " + data.steps.length + " character(s)";

  const tableHint = document.getElementById("tableHint");
  if (tableHint) {
    tableHint.textContent = data.mode === "encrypt"
      ? "Row = key letter, column = plain letter → cell = cipher letter"
      : "Row = key letter, column = plain letter → cell = cipher letter";
  }
}

function copyResult() {
  if (!currentResult) return;
  const done = () => flashButton("btnCopy", "fa-copy", "Copied!");
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(currentResult).then(done).catch(() => fallbackCopy(currentResult, done));
  } else {
    fallbackCopy(currentResult, done);
  }
}

function fallbackCopy(text, done) {
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand("copy"); } catch (e) { /* ignore */ }
  document.body.removeChild(ta);
  done();
}

function downloadResult() {
  if (!currentResult) return;
  const blob = new Blob([currentResult + "\n"], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "vigenere_result.txt";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  flashButton("btnDownload", "fa-download", "Saved!");
}

function flashButton(id, icon, label) {
  const btn = document.getElementById(id);
  if (!btn) return;
  const original = btn.innerHTML;
  btn.innerHTML = `<i class="fa-solid ${icon} me-2"></i>${label}`;
  setTimeout(() => { btn.innerHTML = original; }, 1600);
}

/* ---------- step-by-step table ---------- */
function calculateSteps(steps) {
  const body = document.getElementById("stepsBody");
  if (!body) return;
  body.innerHTML = "";

  if (!steps || steps.length === 0) {
    body.innerHTML = '<tr><td colspan="7" class="text-center text-secondary py-4">No calculations yet.</td></tr>';
    return;
  }

  steps.forEach((step, index) => {
    const tr = document.createElement("tr");
    tr.dataset.index = index;
    tr.addEventListener("mouseenter", () => setActiveHighlight(index));
    tr.innerHTML = `
      <td>${escapeHtml(String(step.position))}</td>
      <td>${escapeHtml(String(step.text))}</td>
      <td>${escapeHtml(String(step.key))}</td>
      <td>${escapeHtml(String(step.text_value))}</td>
      <td>${escapeHtml(String(step.key_value))}</td>
      <td>${escapeHtml(String(step.formula))}</td>
      <td><span class="result-letter">${escapeHtml(String(step.result))}</span></td>
    `;
    body.appendChild(tr);
  });

  // Default: highlight the first key-consuming step
  const firstKeyed = steps.findIndex((s) => s.key !== "-");
  if (firstKeyed > -1) setActiveHighlight(firstKeyed);
}

function escapeHtml(value) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/* ---------- Tabula Recta ---------- */
function renderVigenereTable() {
  const table = document.getElementById("tabulaTable");
  if (!table) return;

  let html = "<thead><tr><th class='corner'>K \\ P</th>";
  for (let c = 0; c < 26; c++) html += `<th data-col="${c}">${ALPHABET[c]}</th>`;
  html += "</tr></thead><tbody>";

  for (let r = 0; r < 26; r++) {
    html += `<tr data-row="${r}"><th>${ALPHABET[r]}</th>`;
    for (let c = 0; c < 26; c++) {
      const value = ALPHABET[(r + c) % 26];
      html += `<td data-row="${r}" data-col="${c}">${value}</td>`;
    }
    html += "</tr>";
  }
  html += "</tbody>";
  table.innerHTML = html;
}

/**
 * highlights: [{row, col, cell, position}] — row = key letter,
 * col = plain letter, cell = the intersecting cipher letter.
 */
function applyHighlights(highlights) {
  highlightCells = (highlights || []).filter((h) => h && typeof h.row === "number" && typeof h.col === "number");
  const table = document.getElementById("tabulaTable");
  if (!table) return;

  table.querySelectorAll(".hl, .hl-key, .hl-plain, .hl-active, .hl-row, .hl-col")
    .forEach((el) => el.classList.remove("hl", "hl-key", "hl-plain", "hl-active", "hl-row", "hl-col"));

  const firstKeyed = highlightCells[0];
  if (firstKeyed) setActiveHighlightByData(firstKeyed);
}

function setActiveHighlight(index) {
  // steps and highlights are aligned (one entry per keyed character),
  // non-keyed rows map to -1 → clear highlighting.
  const keyed = highlightCells;
  if (!keyed.length) return;
  const steps = document.querySelectorAll("#stepsBody tr");
  steps.forEach((tr) => tr.classList.remove("row-active"));
  const tr = steps[index];
  if (tr) tr.classList.add("row-active");

  // find the highlight whose position matches this step row
  const position = index + 1;
  const match = keyed.find((h) => h.position === position);
  if (match) setActiveHighlightByData(match);
}

function setActiveHighlightByData(h) {
  const table = document.getElementById("tabulaTable");
  if (!table) return;

  table.querySelectorAll(".hl, .hl-key, .hl-plain, .hl-active, .hl-row, .hl-col")
    .forEach((el) => el.classList.remove("hl", "hl-key", "hl-plain", "hl-active", "hl-row", "hl-col"));

  const cell = table.querySelector(`td[data-row="${h.row}"][data-col="${h.col}"]`);
  const rowHeader = table.querySelector(`tr[data-row="${h.row}"] > th`);
  const colHeader = table.querySelector(`thead th[data-col="${h.col}"]`);

  if (cell) cell.classList.add("hl-active");
  if (rowHeader) rowHeader.classList.add("hl-row");
  if (colHeader) colHeader.classList.add("hl-col");

  // keep the active cell in view inside the scroll container
  if (cell) {
    const scroller = cell.closest(".tabula-scroll");
    if (scroller) {
      const cellRect = cell.getBoundingClientRect();
      const scrollRect = scroller.getBoundingClientRect();
      if (cellRect.left < scrollRect.left + 40 || cellRect.right > scrollRect.right - 10 ||
          cellRect.top < scrollRect.top + 40 || cellRect.bottom > scrollRect.bottom - 10) {
        cell.scrollIntoView({ block: "nearest", inline: "nearest", behavior: "smooth" });
      }
    }
  }
}

/* ---------- alphabet value section ---------- */
function renderAlphabet() {
  const grid = document.getElementById("alphabetGrid");
  if (!grid) return;

  const chunks = [
    { letters: ALPHABET.slice(0, 13), numbers: range(0, 13) },
    { letters: ALPHABET.slice(13, 26), numbers: range(13, 26) },
  ];

  grid.innerHTML = chunks
    .map(
      (chunk) => `
      <div class="alphabet-row">
        ${chunk.letters.split("").map((l) => `<div class="alpha-cell letter">${l}</div>`).join("")}
      </div>
      <div class="alphabet-row">
        ${chunk.numbers.map((n) => `<div class="alpha-cell number">${n}</div>`).join("")}
      </div>`
    )
    .join("");
}

function range(start, end) {
  const out = [];
  for (let i = start; i < end; i++) out.push(i);
  return out;
}

/* ---------- statistics ---------- */
async function updateStatistics(preloaded) {
  let stats = preloaded;
  if (!stats) {
    try {
      const response = await fetch("/api/statistics");
      const data = await response.json();
      stats = data.statistics;
    } catch (err) {
      console.error("Statistics unavailable", err);
      return;
    }
  }
  if (!stats) return;

  animateNumber("statTotal", stats.total);
  animateNumber("statEncrypted", stats.encrypted);
  animateNumber("statDecrypted", stats.decrypted);
  animateNumber("statAvgKey", stats.avg_key_length);

  renderCipherChips(stats.by_cipher);

  if (statsChart) {
    statsChart.data.datasets[0].data = [stats.encrypted, stats.decrypted];
    statsChart.update();
  }
}

/* "Operations by cipher" breakdown — additive / multiplicative / affine rows
   are added alongside the original Vigenere counter. */
const CIPHER_CHIP_ICONS = {
  "Vigenère": "fa-shield-halved",
  "Additive Cipher": "fa-plus",
  "Multiplicative Cipher": "fa-xmark",
  "Affine Cipher": "fa-calculator",
};

function renderCipherChips(byCipher) {
  const holder = document.getElementById("cipherChips");
  if (!holder || !byCipher) return;

  holder.innerHTML = "";
  Object.entries(byCipher).forEach(([name, count]) => {
    const chip = document.createElement("span");
    chip.className = "cipher-chip";
    const icon = CIPHER_CHIP_ICONS[name] || "fa-circle";
    chip.innerHTML =
      `<i class="fa-solid ${icon}"></i><span>${escapeHtml(name)}</span>` +
      `<span class="chip-count">${escapeHtml(String(count))}</span>`;
    holder.appendChild(chip);
  });
}

function animateNumber(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  const from = parseInt(el.textContent, 10) || 0;
  if (from === target) { el.textContent = target; return; }

  const start = performance.now();
  const duration = 550;
  function tick(now) {
    const p = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(from + (target - from) * eased);
    if (p < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

/* ---------- doughnut chart ---------- */
function buildChart() {
  const canvas = document.getElementById("statsChart");
  if (!canvas || typeof Chart === "undefined") return;

  statsChart = new Chart(canvas, {
    type: "doughnut",
    data: {
      labels: ["Encrypted", "Decrypted"],
      datasets: [
        {
          data: [0, 0],
          backgroundColor: ["rgba(34, 211, 238, 0.85)", "rgba(167, 139, 250, 0.85)"],
          borderColor: "rgba(10, 15, 31, 0.9)",
          borderWidth: 3,
          hoverOffset: 8,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: "65%",
      plugins: {
        legend: {
          position: "bottom",
          labels: { color: "#8d97ad", boxWidth: 12, padding: 14, font: { size: 11 } },
        },
      },
    },
  });
}

/* ---------- clear ---------- */
function clearDashboard() {
  const message = document.getElementById("messageInput");
  const key = document.getElementById("keyInput");
  if (message) message.value = "";
  if (key) key.value = "";

  clearError();

  const box = document.getElementById("resultBox");
  box.textContent = "Your result will appear here.";
  box.classList.add("empty");

  const badge = document.getElementById("resultBadge");
  badge.textContent = "waiting…";
  badge.classList.remove("enc", "dec");

  currentResult = "";
  document.getElementById("btnCopy").disabled = true;
  document.getElementById("btnDownload").disabled = true;
  document.getElementById("repeatedKey").textContent = "—";
  document.getElementById("stepsHint").textContent = "Run an operation to generate the table";
  document.getElementById("tableHint").textContent = "Highlighted cells show the operation used";

  calculateSteps([]);
  highlightCells = [];
  const table = document.getElementById("tabulaTable");
  if (table) {
    table.querySelectorAll(".hl-active, .hl-row, .hl-col")
      .forEach((el) => el.classList.remove("hl-active", "hl-row", "hl-col"));
  }
}

/* =====================================================================
   History page helpers
   ===================================================================== */
function fillViewModal(op) {
  document.getElementById("vmDate").textContent = op.created_at || "—";
  document.getElementById("vmCipher").textContent = op.cipher || "Vigenère";
  document.getElementById("vmType").textContent = op.operation_type || "—";
  document.getElementById("vmInput").textContent = op.input_text || "—";
  document.getElementById("vmKey").textContent = op.key || "—";
  document.getElementById("vmKeyLen").textContent = (op.key || "").length + " character(s)";
  document.getElementById("vmResult").textContent = op.result || "—";
  document.getElementById("vmResult").dataset.value = op.result || "";
}

function copyModalResult() {
  const value = document.getElementById("vmResult").dataset.value || "";
  if (!value) return;
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(value);
  } else {
    fallbackCopy(value, () => {});
  }
}
