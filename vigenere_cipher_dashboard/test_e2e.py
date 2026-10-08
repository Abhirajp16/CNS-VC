"""End-to-end smoke test for the Vigenere Cipher Dashboard."""
import json
import os
import urllib.request
import urllib.parse
import http.cookiejar

BASE = "http://127.0.0.1:" + os.environ.get("PORT", "5000")
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

failures = []


def check(name, cond, extra=""):
    status = "PASS" if cond else "FAIL"
    if not cond:
        failures.append(name)
    print(f"[{status}] {name} {extra}")


def get(path):
    with opener.open(BASE + path) as r:
        body = r.read().decode("utf-8")
        if "application/json" in r.headers.get("Content-Type", ""):
            return r.status, json.loads(body)
        return r.status, body


def post(path, data=None, json_body=None, headers=None):
    if json_body is not None:
        body = json.dumps(json_body).encode()
        req = urllib.request.Request(BASE + path, data=body,
                                     headers={"Content-Type": "application/json",
                                              "Accept": "application/json", **(headers or {})})
    else:
        body = urllib.parse.urlencode(data or {}).encode()
        req = urllib.request.Request(BASE + path, data=body,
                                     headers={"Content-Type": "application/x-www-form-urlencoded",
                                              "Accept": "application/json", **(headers or {})})
    try:
        with opener.open(req) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw


# 1. Pages
s, body = get("/")
check("GET / (landing)", s == 200 and "Vigen" in body)

s, body = get("/login")
check("GET /login", s == 200 and "Username" in body)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


# opener that shares our session cookie but never follows redirects
no_redirect_session = urllib.request.build_opener(NoRedirect, urllib.request.HTTPCookieProcessor(jar))

# 2. Protected route redirects when logged out (do not follow redirects)
no_redirect_anon = urllib.request.build_opener(NoRedirect)
try:
    with no_redirect_anon.open(BASE + "/dashboard") as r:
        check("GET /dashboard redirects", False, f"status={r.status}")
except urllib.error.HTTPError as e:
    check("GET /dashboard redirects to login", e.code == 302 and "/login" in e.headers.get("Location", ""))

# 3. Bad login
s, data = post("/login", {"username": "admin", "password": "wrong"})
check("Bad login rejected", s == 401 and data.get("ok") is False, str(data))

# 4. Good login
s, data = post("/login", {"username": "admin", "password": "admin123"})
check("Login accepted", s == 200 and data.get("ok") is True, str(data))

# 5. Protected pages now work
for path, marker in [("/dashboard", "Cipher Panel"), ("/encrypt", "Cipher Panel"),
                     ("/decrypt", "Cipher Panel"), ("/history", "Operation"),
                     ("/how-it-works", "polyalphabetic substitution cipher")]:
    s, body = get(path)
    check(f"GET {path}", s == 200 and marker in body, f"status={s}")

# 6. Encrypt
s, data = post("/api/process", json_body={"mode": "encrypt", "message": "HELLO WORLD", "key": "KEY"})
check("Encrypt HELLO WORLD/KEY", s == 200 and data.get("result") == "RIJVS UYVJN",
      f"got={data.get('result')}")
check("Repeated key aligned", data.get("repeated_key") == "KEYKE YKEYK", f"got={data.get('repeated_key')}")
check("Steps generated", len(data.get("steps", [])) == 11, f"n={len(data.get('steps', []))}")
check("Step 1 values", data["steps"][0] and data["steps"][0]["text"] == "H"
      and data["steps"][0]["key"] == "K" and data["steps"][0]["result"] == "R"
      and data["steps"][0]["formula"] == "(7+10)%26", str(data["steps"][0]))
check("Space consumes no key", data["steps"][5]["key"] == "-", str(data["steps"][5]))
check("Highlights produced", len(data.get("highlights", [])) == 10)
check("Stats updated", data["statistics"]["total"] >= 1 and data["statistics"]["encrypted"] >= 1,
      str(data["statistics"]))

# 7. Decrypt round trip
s, data = post("/api/process", json_body={"mode": "decrypt", "message": "RIJVS UYVJN", "key": "KEY"})
check("Decrypt back to HELLO WORLD", s == 200 and data.get("result") == "HELLO WORLD",
      f"got={data.get('result')}")
# C=17, K=10 -> (17-10+26)%26 = 7 = H
check("Decryption formula", "(17-10+26)%26" in [st["formula"] for st in data["steps"]],
      str([st["formula"] for st in data["steps"][:3]]))
check("Decrypt step values", data["steps"][0]["text"] == "R" and data["steps"][0]["result"] == "H",
      str(data["steps"][0]))

# 8. Lowercase + numbers + special chars
s, data = post("/api/process", json_body={"mode": "encrypt", "message": "Hello, World! 123", "key": "key"})
check("Mixed case / punctuation", s == 200 and data.get("result", "").startswith("RIJVS") and "!" in data["result"],
      f"got={data.get('result')}")

# 9. Validation
s, data = post("/api/process", json_body={"mode": "encrypt", "message": "", "key": "KEY"})
check("Empty message", s == 400 and data.get("error") == "Please enter a message.", str(data))
s, data = post("/api/process", json_body={"mode": "encrypt", "message": "HI", "key": ""})
check("Empty key", s == 400 and data.get("error") == "Please enter a key.", str(data))
s, data = post("/api/process", json_body={"mode": "encrypt", "message": "HI", "key": "123!"})
check("Non-alphabetic key", s == 400 and "alphabetic" in data.get("error", ""), str(data))
s, data = post("/api/process", json_body={"mode": "nope", "message": "HI", "key": "K"})
check("Bad mode", s == 400)

# 10. Statistics API
s, data = get("/api/statistics")
stats_ok = s == 200 and "statistics" in data
if stats_ok:
    st = data["statistics"]
    stats_ok = st["total"] == st["encrypted"] + st["decrypted"] and st["avg_key_length"] >= 1
check("GET /api/statistics", stats_ok, str(data))

# 11. History API
s, data = get("/api/history")
check("GET /api/history", s == 200 and len(data.get("operations", [])) >= 3,
      f"n={len(data.get('operations', []))}")
op_id = data["operations"][0]["id"]

# 12. Delete an operation (JSON flavour) and verify HTML form flavour redirects
s, data = post(f"/history/delete/{op_id}", json_body={})
check("Delete operation (JSON)", s == 200 and data.get("ok") is True, str(data))
s, data = get("/api/history")
check("Delete took effect", all(o["id"] != op_id for o in data["operations"]))

# 13. History page contains rows
s, body = get("/history")
check("History page shows operations", "Encryption" in body and "Decryption" in body)

# 14. Unauthenticated API access
anon = urllib.request.build_opener()
try:
    with anon.open(BASE + "/api/statistics") as r:
        check("Anonymous API blocked", False)
except urllib.error.HTTPError as e:
    check("Anonymous API blocked", e.code == 401)

# 15. Logout
s, body = get("/logout")
check("Logout clears session", s == 200)
try:
    with no_redirect_session.open(BASE + "/dashboard") as r:
        check("Dashboard protected after logout", False, f"status={r.status}")
except urllib.error.HTTPError as e:
    check("Dashboard protected after logout", e.code == 302)

print()
if failures:
    print(f"FAILED ({len(failures)}): {failures}")
    raise SystemExit(1)
print("ALL TESTS PASSED")
