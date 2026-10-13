/* =====================================================================
   Additive / Multiplicative / Affine cipher panels
   Talks to the Flask API (/api/cipher) and reuses the shared helpers
   defined in script.js (escapeHtml, showError, renderAlphabet,
   updateStatistics, flashButton, fallbackCopy).
   ===================================================================== */

"use strict";

let currentCipherResult = "";
let cipherMode = "encrypt";

const INT_PATTERN = /^[+-]?[0-9]+$/;

/* ---------- initialisation ---------- */
document.addEventListener("DOMContentLoaded", () => {
  const cipherId = document.body.dataset.cipher;
  if (!cipherId) return; // not a cipher page

  renderAlphabet();
  updateStatistics();
  setCipherMode("encrypt");

  const message = document.getElementById("messageInput");
  if (message) message.addEventListener("input", refreshKeyInUse);
  document.querySelectorAll(".cipher-key").forEach((field) => {
    field.addEventListener("input", refreshKeyInUse);
    field.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        cipherMode === "decrypt" ? decryptCipher() : encryptCipher();
      }
    });
  });

  const form = document.getElementById("cipherForm");
  if (form) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      cipherMode === "decrypt" ? decryptCipher() : encryptCipher();
    });
  }
});

/* ---------- key helpers ---------- */
function collectKeys() {
  const keys = {};
  document.querySelectorAll(".cipher-key").forEach((field) => {
    keys[field.dataset.keyName] = field.value;
  });
  return keys;
}

function keyLabel(name) {
  const field = document.querySelector(`.cipher-key[data-key-name="${name}"]`);
  if (!field) return "Key";
  const label = document.querySelector(`label[for="${field.id}"]`);
  return label ? label.textContent.trim() : "Key";
}

/** Mirror of the server-side rules so bad input is caught instantly. */
function validateCipherInput(message, keys) {
  if (message === null || message === undefined || String(message).trim() === "") {
    return { ok: false, message: "Please enter a message.", field: "message" };
  }

  const values = Object.values(keys);
  if (values.length === 0 || values.every((v) => String(v).trim() === "")) {
    return { ok: false, message: "Please enter a key.", field: "key" };
  }

  for (const [name, value] of Object.entries(keys)) {
    if (String(value).trim() === "") {
      return { ok: false, message: `Please enter ${keyLabel(name)}.`, field: name };
    }
    if (!INT_PATTERN.test(String(value).trim())) {
      return {
        ok: false,
        message: `${keyLabel(name)} must be a whole number, e.g. 3.`,
        field: name,
      };
    }
  }
  return { ok: true, message: "", field: "" };
}

function focusInvalid(field, message) {
  if (field && field !== "key" && field !== "message") {
    const el = document.querySelector(`.cipher-key[data-key-name="${field}"]`);
    if (el) { el.focus(); return; }
  }
  if (field === "key") {
    const first = document.querySelector(".cipher-key");
    if (first) { first.focus(); return; }
  }
  const box = document.getElementById(field === "message" ? "messageInput" : "messageInput");
  if (box) box.focus();
  void message;
}

/* ---------- live "key in use" preview ---------- */
function refreshKeyInUse() {
  const box = document.getElementById("keyInUse");
  if (!box) return;

  const keys = collectKeys();
  const parts = Object.entries(keys)
    .map(([name, value]) => `${name} = ${String(value).trim() === "" ? "?" : value.trim()}`)
    .join(", ");

  box.textContent = Object.keys(keys).length ? parts : "—";
}

/* ---------- mode ---------- */
function setCipherMode(mode) {
  cipherMode = mode;

  const pill = document.getElementById("modePill");
  if (pill) {
    pill.textContent = mode === "encrypt" ? "Encryption" : "Decryption";
    pill.classList.toggle("dec", mode === "decrypt");
  }

  const hint = document.getElementById("stepsHint");
  if (hint) {
    const enc = (document.querySelector(".formula-pill.enc") || {}).textContent || "";
    const dec = (document.querySelector(".formula-pill.dec") || {}).textContent || "";
    hint.textContent = mode === "encrypt"
      ? `Encryption uses ${enc}`
      : `Decryption uses ${dec}`;
  }
}

/* ---------- encrypt / decrypt ---------- */
function encryptCipher() {
  processCipher("encrypt");
}

function decryptCipher() {
  processCipher("decrypt");
}

async function processCipher(mode) {
  const messageEl = document.getElementById("messageInput");
  const message = messageEl.value;
  const keys = collectKeys();

  clearError();

  const check = validateCipherInput(message, keys);
  if (!check.ok) {
    showError(check.message);
    focusInvalid(check.field, check.message);
    return;
  }

  setCipherMode(mode);
  setCipherLoading(true);

  try {
    const response = await fetch("/api/cipher", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cipher: document.body.dataset.cipher, mode, message, keys }),
    });

    const data = await response.json();

    if (!response.ok || !data.ok) {
      showError(data.error || "Something went wrong. Please try again.");
      return;
    }

    renderCipherResult(data);
    renderCipherSteps(data.steps);
    updateStatistics(data.statistics);
  } catch (err) {
    showError("Could not reach the server. Is Flask running?");
    console.error(err);
  } finally {
    setCipherLoading(false);
  }
}

function setCipherLoading(isLoading) {
  ["btnEncrypt", "btnDecrypt"].forEach((id) => {
    const btn = document.getElementById(id);
    if (btn) btn.disabled = isLoading;
  });
}

/* ---------- result card ---------- */
function renderCipherResult(data) {
  currentCipherResult = data.result;

  const box = document.getElementById("resultBox");
  box.textContent = data.result;
  box.classList.remove("empty");

  const badge = document.getElementById("resultBadge");
  badge.textContent = data.operation_type;
  badge.classList.remove("enc", "dec");
  badge.classList.add(data.mode === "encrypt" ? "enc" : "dec");

  document.getElementById("btnCopy").disabled = false;
  document.getElementById("btnDownload").disabled = false;

  const keyBox = document.getElementById("keyInUse");
  if (keyBox) keyBox.textContent = data.key;

  const hint = document.getElementById("stepsHint");
  if (hint) hint.textContent = `${data.operation_type} — ${data.steps.length} character(s)`;

  // modular inverse panel (multiplicative / affine, decryption only)
  const inverseBox = document.getElementById("inverseBox");
  if (inverseBox) {
    const value = document.getElementById("inverseValue");
    if (data.inverse_note) {
      value.textContent = data.inverse_note;
      inverseBox.classList.remove("d-none");
    } else {
      inverseBox.classList.add("d-none");
    }
  }
}

function copyCipherResult() {
  if (!currentCipherResult) return;
  const done = () => flashButton("btnCopy", "fa-copy", "Copied!");
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(currentCipherResult)
      .then(done)
      .catch(() => fallbackCopy(currentCipherResult, done));
  } else {
    fallbackCopy(currentCipherResult, done);
  }
}

function downloadCipherResult() {
  if (!currentCipherResult) return;
  const cipherId = document.body.dataset.cipher || "cipher";
  const blob = new Blob([currentCipherResult + "\n"], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `${cipherId}_result.txt`;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
  flashButton("btnDownload", "fa-download", "Saved!");
}

/* ---------- step-by-step table ----------
   Columns: Position | Input Character | Numerical Value | Key Values |
            Formula | Calculated Value | Output Character
   ------------------------------------------------------------ */
function renderCipherSteps(steps) {
  const body = document.getElementById("stepsBody");
  if (!body) return;
  body.innerHTML = "";

  if (!steps || steps.length === 0) {
    body.innerHTML = '<tr><td colspan="7" class="text-center text-secondary py-4">No calculations yet.</td></tr>';
    return;
  }

  steps.forEach((step) => {
    const tr = document.createElement("tr");
    const isLetter = step.numeric_value !== "-";
    if (!isLetter) tr.classList.add("row-muted");

    const input = step.input_char === " " ? "␣" : step.input_char;
    const output = step.output_char === " " ? "␣" : step.output_char;

    tr.innerHTML = `
      <td>${escapeHtml(String(step.position))}</td>
      <td>${escapeHtml(String(input))}</td>
      <td>${escapeHtml(String(step.numeric_value))}</td>
      <td>${escapeHtml(String(step.key_values))}</td>
      <td>${escapeHtml(String(step.formula))}</td>
      <td>${escapeHtml(String(step.calculated_value))}</td>
      <td><span class="result-letter">${escapeHtml(String(output))}</span></td>
    `;
    body.appendChild(tr);
  });
}

/* ---------- clear ---------- */
function clearCipherPanel() {
  const message = document.getElementById("messageInput");
  if (message) message.value = "";
  document.querySelectorAll(".cipher-key").forEach((field) => { field.value = ""; });

  clearError();

  const box = document.getElementById("resultBox");
  box.textContent = "Your result will appear here.";
  box.classList.add("empty");

  const badge = document.getElementById("resultBadge");
  badge.textContent = "waiting…";
  badge.classList.remove("enc", "dec");

  currentCipherResult = "";
  document.getElementById("btnCopy").disabled = true;
  document.getElementById("btnDownload").disabled = true;

  const keyBox = document.getElementById("keyInUse");
  if (keyBox) keyBox.textContent = "—";

  const inverseBox = document.getElementById("inverseBox");
  if (inverseBox) inverseBox.classList.add("d-none");

  setCipherMode("encrypt");
  document.getElementById("stepsHint").textContent = "Run an operation to generate the table";

  renderCipherSteps([]);
}
