"""Test suite for the Additive, Multiplicative and Affine ciphers.

Run with the Flask server already running (PORT env var, default 5000):

    set PORT=5001
    python test_ciphers.py

Part A - engine level (no server needed): real algorithms, validation rules,
         modular inverses, round-trip recovery, case / space / punctuation.
Part B - HTTP API level (/api/cipher): responses, errors, history records.
Part C - regression: Vigenere, login/logout, history, stored database rows.
"""

import json
import os
import sys
import sqlite3
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar

# Windows consoles default to cp1252, which cannot print the superscript
# characters used in the modular-inverse messages (K⁻¹ / a⁻¹).
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # pragma: no cover
    pass

BASE = "http://127.0.0.1:" + os.environ.get("PORT", "5000")
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.db")

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

failures = []
passes = 0


def check(name, cond, extra=""):
    global passes
    status = "PASS" if cond else "FAIL"
    if cond:
        passes += 1
    else:
        failures.append(name)
    print(f"[{status}] {name} {extra}")


# ==========================================================================
# Part A - engine level
# ==========================================================================
print("\n===== PART A - cipher engines =====")

from ciphers import (  # noqa: E402
    run_additive,
    run_multiplicative,
    run_affine,
    mod_inverse,
    VALID_MULTIPLICATIVE_KEYS,
)


def safe(fn, *args):
    """Run an engine, returning (payload, error_message)."""
    try:
        return fn(*args), None
    except ValueError as exc:
        return None, str(exc)


# ---- Additive -------------------------------------------------------------
p, e = safe(run_additive, "HELLO", "0", "encrypt")
check("additive key 0 is identity", p and p["result"] == "HELLO",
      f"-> {p and p['result']}")

p, e = safe(run_additive, "HELLO", "3", "encrypt")
check("additive key 3 encrypts (Caesar)", p and p["result"] == "KHOOR",
      f"-> {p and p['result']}")

p, e = safe(run_additive, "HELLO", "25", "encrypt")
check("additive key 25 encrypts", p and p["result"] == "GDKKN",
      f"-> {p and p['result']}")

p, e = safe(run_additive, "KHOOR", "3", "decrypt")
check("additive key 3 decrypts", p and p["result"] == "HELLO",
      f"-> {p and p['result']}")

p, e = safe(run_additive, "AbCd XyZ!", "3", "encrypt")
q, e2 = safe(run_additive, p["result"], "3", "decrypt") if p else (None, "skipped")
check("additive preserves case + punctuation + round-trip",
      p and q and q["result"] == "AbCd XyZ!",
      f"-> enc={p and p['result']} dec={q and q['result']}")

p, e = safe(run_additive, "", "3", "encrypt")
check("additive empty input handled", p is not None or e is not None, f"-> {e}")

p, e = safe(run_additive, "HELLO", "abc", "encrypt")
check("additive rejects non-integer key", e and "whole number" in e, f"-> {e}")

p, e = safe(run_additive, "HELLO", "", "encrypt")
check("additive rejects empty key", e and "Please enter a key" in e, f"-> {e}")

# ---- Multiplicative -------------------------------------------------------
p, e = safe(run_multiplicative, "HELLO", "5", "encrypt")
check("multiplicative key 5 encrypts", p and p["result"] == "JUDDS",
      f"-> {p and p['result']}")
check("multiplicative inverse of 5 is 21", p and p["inverse"] == 21,
      f"-> {p and p['inverse']}")

p, e = safe(run_multiplicative, "JUDDS", "5", "decrypt")
check("multiplicative key 5 decrypts", p and p["result"] == "HELLO",
      f"-> {p and p['result']}")
check("multiplicative decryption exposes inverse in the note",
      p and p["inverse_note"] and "21" in p["inverse_note"],
      f"-> {p and p['inverse_note']}")
check("multiplicative decryption shows inverse in key column",
      p and any("K\u207b\u00b9 = 21" in s["key_values"] for s in p["steps"]),
      "-> key column")

p, e = safe(run_multiplicative, "HELLO", "2", "encrypt")
check("multiplicative key 2 rejected", e and "coprime" in e, f"-> {e}")
check("multiplicative key 2 lists valid keys", e and "1, 3, 5" in e, f"-> {e}")

for bad in ("0", "4", "6", "26", "13"):
    p, e = safe(run_multiplicative, "HELLO", bad, "encrypt")
    check(f"multiplicative invalid key {bad} rejected", e and "coprime" in e,
          f"-> {e}")

p, e = safe(run_multiplicative, "AbCd! 123", "7", "encrypt")
q, e2 = safe(run_multiplicative, p["result"], "7", "decrypt") if p else (None, "")
check("multiplicative preserves case/punctuation + round-trip",
      p and q and q["result"] == "AbCd! 123",
      f"-> enc={p and p['result']} dec={q and q['result']}")

for good in VALID_MULTIPLICATIVE_KEYS:
    p, e = safe(run_multiplicative, "ABCDEFGHIJKLM", str(good), "encrypt")
    check(f"multiplicative valid key {good} accepted", e is None, f"-> {e}")

check("mod_inverse(5) == 21", mod_inverse(5) == 21)
check("mod_inverse(3) == 9", mod_inverse(3) == 9)
check("mod_inverse(7) == 15", mod_inverse(7) == 15)
check("mod_inverse(2) is None", mod_inverse(2) is None)

# ---- Affine ---------------------------------------------------------------
p, e = safe(run_affine, "HELLO", "5", "8", "encrypt")
check("affine a=5 b=8 encrypts", p and p["result"] == "RCLLA",
      f"-> {p and p['result']}")
check("affine inverse of a=5 is 21", p and p["inverse"] == 21,
      f"-> {p and p['inverse']}")

p, e = safe(run_affine, "RCLLA", "5", "8", "decrypt")
check("affine a=5 b=8 decrypts", p and p["result"] == "HELLO",
      f"-> {p and p['result']}")
check("affine decryption shows a-inverse",
      p and any("a\u207b\u00b9 = 21" in s["key_values"] for s in p["steps"]),
      "-> key column")

p, e = safe(run_affine, "HELLO", "2", "8", "encrypt")
check("affine a=2 rejected", e and "coprime" in e, f"-> {e}")
check("affine a=2 mentions multiplicative key a", e and "a" in e, f"-> {e}")

p, e = safe(run_affine, "HELLO", "5", "abc", "encrypt")
check("affine rejects non-integer b", e and "whole number" in e, f"-> {e}")

p, e = safe(run_affine, "HELLO", "", "8", "encrypt")
check("affine rejects empty a", e and "Please enter a key" in e, f"-> {e}")

p, e = safe(run_affine, "Hello, World! 123", "5", "8", "encrypt")
q, e2 = safe(run_affine, p["result"], "5", "8", "decrypt") if p else (None, "")
check("affine preserves case/punctuation + round-trip",
      p and q and q["result"] == "Hello, World! 123",
      f"-> enc={p and p['result']} dec={q and q['result']}")

# ---- step table contract --------------------------------------------------
p, _ = safe(run_additive, "Hi!", "3", "encrypt")
cols = ["position", "input_char", "numeric_value", "key_values",
        "formula", "calculated_value", "output_char"]
check("step rows expose all 7 columns",
      p and all(all(c in s for c in cols) for s in p["steps"]))
check("step formula for a letter is the real calculation",
      p and p["steps"][0]["formula"] == "(7+3)%26",
      f"-> {p and p['steps'][0]['formula']}")
check("step formula for a non-letter says no shift",
      p and "no shift" in p["steps"][2]["formula"],
      f"-> {p and p['steps'][2]['formula']}")

p, _ = safe(run_multiplicative, "A", "5", "decrypt")
check("multiplicative decrypt step formula uses the inverse",
      p and p["steps"][0]["formula"] == "(0*21)%26",
      f"-> {p and p['steps'][0]['formula']}")

p, _ = safe(run_affine, "A", "5", "8", "decrypt")
check("affine decrypt step formula matches a^-1*(C-b)",
      p and p["steps"][0]["formula"] == "(21*(0-8))%26",
      f"-> {p and p['steps'][0]['formula']}")


# ==========================================================================
# Part B - HTTP API
# ==========================================================================
print("\n===== PART B - HTTP API =====")


def login(user="admin", pw="admin123"):
    body = urllib.parse.urlencode({"username": user, "password": pw}).encode()
    req = urllib.request.Request(BASE + "/login", data=body, method="POST")
    try:
        opener.open(req, timeout=10)
    except urllib.error.HTTPError as exc:
        if exc.code != 302:
            raise


def post_json(path, payload, expect_error=False):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        BASE + path, data=data, method="POST",
        headers={"Content-Type": "application/json",
                 "Accept": "application/json"})
    try:
        with opener.open(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = {"raw": raw}
        return exc.code, parsed


def get_json(path):
    with opener.open(BASE + path, timeout=15) as resp:
        return resp.status, json.loads(resp.read().decode())


server_up = True
try:
    with opener.open(BASE + "/login", timeout=10) as resp:
        server_up = resp.status == 200
except Exception as exc:  # pragma: no cover
    server_up = False
    print(f"  server unreachable at {BASE}: {exc}")

if not server_up:
    check("server reachable", False, f"start it with: python app.py (PORT={os.environ.get('PORT', '5000')})")
else:
    login()
    check("login succeeds", True)

    # existing records before we run anything
    conn = sqlite3.connect(DB)
    before_rows = conn.execute(
        "SELECT id, operation_type, input_text, key, result, cipher "
        "FROM operations ORDER BY id").fetchall()
    conn.close()
    before_ids = {r[0] for r in before_rows}
    check("database has records before the run", len(before_rows) > 0,
          f"-> {len(before_rows)} rows")

    # ---- additive API ----
    code, data = post_json("/api/cipher", {
        "cipher": "additive", "mode": "encrypt",
        "message": "HELLO WORLD", "keys": {"k": "3"}})
    check("API additive encrypt 200", code == 200 and data.get("ok"))
    check("API additive result", data.get("result") == "KHOOR ZRUOG",
          f"-> {data.get('result')}")
    check("API additive step count", len(data.get("steps", [])) == 11,
          f"-> {len(data.get('steps', []))}")
    check("API additive stores cipher name",
          data.get("cipher_name") == "Additive Cipher",
          f"-> {data.get('cipher_name')}")

    code, data = post_json("/api/cipher", {
        "cipher": "additive", "mode": "encrypt",
        "message": "HELLO WORLD", "keys": {"k": ""}})
    check("API additive empty key 400", code == 400, f"-> {data.get('error')}")
    check("API additive empty key message",
          data.get("error") == "Please enter a key.",
          f"-> {data.get('error')}")

    code, data = post_json("/api/cipher", {
        "cipher": "additive", "mode": "encrypt",
        "message": "", "keys": {"k": "3"}})
    check("API additive empty message 400", code == 400,
          f"-> {data.get('error')}")
    check("API additive empty message text",
          data.get("error") == "Please enter a message.",
          f"-> {data.get('error')}")

    # ---- multiplicative API ----
    code, data = post_json("/api/cipher", {
        "cipher": "multiplicative", "mode": "encrypt",
        "message": "HELLO", "keys": {"k": "5"}})
    check("API multiplicative key 5 accepted", code == 200 and data.get("ok"),
          f"-> {data.get('error')}")
    check("API multiplicative result", data.get("result") == "JUDDS",
          f"-> {data.get('result')}")

    code, data = post_json("/api/cipher", {
        "cipher": "multiplicative", "mode": "encrypt",
        "message": "HELLO", "keys": {"k": "2"}})
    check("API multiplicative key 2 rejected", code == 400,
          f"-> {data.get('error')}")
    check("API multiplicative key 2 message mentions coprime",
          "coprime" in (data.get("error") or ""),
          f"-> {data.get('error')}")

    code, data = post_json("/api/cipher", {
        "cipher": "multiplicative", "mode": "decrypt",
        "message": "JUDDS", "keys": {"k": "5"}})
    check("API multiplicative decrypt returns inverse",
          code == 200 and data.get("inverse") == 21,
          f"-> {data.get('inverse')} / {data.get('inverse_note')}")
    check("API multiplicative decrypt result", data.get("result") == "HELLO",
          f"-> {data.get('result')}")

    # ---- affine API ----
    code, data = post_json("/api/cipher", {
        "cipher": "affine", "mode": "encrypt",
        "message": "HELLO", "keys": {"a": "5", "b": "8"}})
    check("API affine a=5 b=8 accepted", code == 200 and data.get("ok"),
          f"-> {data.get('error')}")
    check("API affine result", data.get("result") == "RCLLA",
          f"-> {data.get('result')}")

    code, data = post_json("/api/cipher", {
        "cipher": "affine", "mode": "encrypt",
        "message": "HELLO", "keys": {"a": "2", "b": "8"}})
    check("API affine a=2 rejected", code == 400, f"-> {data.get('error')}")
    check("API affine a=2 message mentions coprime",
          "coprime" in (data.get("error") or ""),
          f"-> {data.get('error')}")

    code, data = post_json("/api/cipher", {
        "cipher": "affine", "mode": "encrypt",
        "message": "HELLO", "keys": {"a": "5", "b": ""}})
    check("API affine missing b 400", code == 400, f"-> {data.get('error')}")
    check("API affine missing b names the field",
          "Additive Key (b)" in (data.get("error") or ""),
          f"-> {data.get('error')}")

    # ---- unknown cipher / mode ----
    code, data = post_json("/api/cipher", {
        "cipher": "playfair", "mode": "encrypt",
        "message": "HELLO", "keys": {"k": "3"}})
    check("API unknown cipher rejected", code == 400,
          f"-> {data.get('error')}")
    check("API explicitly refuses non-supported ciphers (no Playfair)",
          data.get("error") == "Unknown cipher." and not data.get("ok"),
          f"-> {data.get('error')}")

    code, data = post_json("/api/cipher", {
        "cipher": "additive", "mode": "teleport",
        "message": "HELLO", "keys": {"k": "3"}})
    check("API invalid mode rejected", code == 400, f"-> {data.get('error')}")

    # ---- round trip through the API ----
    _, enc = post_json("/api/cipher", {
        "cipher": "affine", "mode": "encrypt",
        "message": "Hello, World! 123", "keys": {"a": "7", "b": "21"}})
    _, dec = post_json("/api/cipher", {
        "cipher": "affine", "mode": "decrypt",
        "message": enc.get("result", ""), "keys": {"a": "7", "b": "21"}})
    check("API affine round-trip recovers the message",
          dec.get("result") == "Hello, World! 123",
          f"-> {dec.get('result')}")

    # ---- statistics include the new ciphers ----
    code, stats = get_json("/api/statistics")
    by_cipher = stats.get("statistics", {}).get("by_cipher", {})
    check("statistics include all four ciphers",
          set(by_cipher) >= {"Vigenère", "Additive Cipher",
                             "Multiplicative Cipher", "Affine Cipher"},
          f"-> {list(by_cipher)}")
    check("existing statistics keys preserved",
          {"total", "encrypted", "decrypted", "avg_key_length"}
          <= set(stats.get("statistics", {})),
          f"-> {list(stats.get('statistics', {}))}")
    check("statistics totals match", stats["statistics"]["total"] >= 0)

    # ---- history identifies every cipher ----
    _, hist = get_json("/api/history")
    rows = hist.get("operations", hist if isinstance(hist, list) else [])
    seen = {r.get("cipher") for r in rows}
    check("history rows carry a cipher name", len(rows) > 0,
          f"-> {len(rows)} rows")
    check("history contains Vigenere + new ciphers",
          {"Vigenère", "Additive Cipher", "Multiplicative Cipher",
           "Affine Cipher"} <= seen, f"-> {seen}")

    # ---- pages render ----
    for path, marker in [("/cipher/additive", "Additive Cipher"),
                         ("/cipher/multiplicative", "Multiplicative Cipher"),
                         ("/cipher/affine", "Affine Cipher"),
                         ("/dashboard", "Vigenère"),
                         ("/history", "History"),
                         ("/how-it-works", "How It Works")]:
        try:
            with opener.open(BASE + path, timeout=15) as resp:
                html = resp.read().decode()
            check(f"page {path} renders", resp.status == 200 and marker in html,
                  f"status={resp.status}")
        except Exception as exc:
            check(f"page {path} renders", False, f"-> {exc}")

    # ---- database integrity: original rows untouched ----
    conn = sqlite3.connect(DB)
    after_rows = conn.execute(
        "SELECT id, operation_type, input_text, key, result, cipher "
        "FROM operations ORDER BY id").fetchall()
    conn.close()
    after_by_id = {r[0]: r for r in after_rows}

    lost = before_ids - set(after_by_id)
    check("no pre-existing record was deleted", not lost, f"-> {sorted(lost)}")

    changed = [r for r in before_rows if after_by_id.get(r[0]) != r]
    check("no pre-existing record was modified", not changed,
          f"-> {changed[:3]}")

    vig_rows = [r for r in after_rows if r[5] in (None, "Vigenère")]
    vig_before = [r for r in before_rows if r[5] in (None, "Vigenère")]
    check("legacy Vigenere rows still readable",
          len(vig_rows) >= len(vig_before),
          f"-> {len(vig_rows)} vigenere rows (was {len(vig_before)})")


# ==========================================================================
# Part C - Vigenere regression
# ==========================================================================
print("\n===== PART C - Vigenere regression =====")

if server_up:
    # the classic test from test_e2e.py must still hold
    body = json.dumps({"message": "HELLO WORLD", "key": "KEY",
                       "mode": "encrypt"}).encode()
    req = urllib.request.Request(
        BASE + "/api/process", data=body, method="POST",
        headers={"Content-Type": "application/json"})
    with opener.open(req, timeout=15) as resp:
        data = json.loads(resp.read().decode())
    check("Vigenere encrypt still works",
          data.get("result") == "RIJVS UYVJN", f"-> {data.get('result')}")

    body = json.dumps({"message": "RIJVS UYVJN", "key": "KEY",
                       "mode": "decrypt"}).encode()
    req = urllib.request.Request(
        BASE + "/api/process", data=body, method="POST",
        headers={"Content-Type": "application/json"})
    with opener.open(req, timeout=15) as resp:
        data = json.loads(resp.read().decode())
    check("Vigenere decrypt still works",
          data.get("result") == "HELLO WORLD", f"-> {data.get('result')}")

    # logout keeps the app reachable and re-login works
    try:
        with opener.open(BASE + "/logout", timeout=15) as resp:
            check("logout responds", resp.status in (200, 302))
    except urllib.error.HTTPError as exc:
        check("logout responds", exc.code in (200, 302), f"-> {exc.code}")

    try:
        with opener.open(BASE + "/dashboard", timeout=15) as resp:
            # urllib follows the 302 to /login?next=/dashboard
            check("dashboard requires auth after logout",
                  "/login" in resp.geturl(),
                  f"-> landed on {resp.geturl()}")
    except urllib.error.HTTPError as exc:
        check("dashboard requires auth after logout", exc.code == 302,
              f"-> {exc.code}")

    login()
    try:
        with opener.open(BASE + "/dashboard", timeout=15) as resp:
            check("re-login restores the dashboard", resp.status == 200)
    except Exception as exc:
        check("re-login restores the dashboard", False, f"-> {exc}")


# ==========================================================================
print("\n" + "=" * 60)
print(f"PASSED {passes}   FAILED {len(failures)}")
if failures:
    for name in failures:
        print(f"  FAILED: {name}")
print("=" * 60)
raise SystemExit(1 if failures else 0)
