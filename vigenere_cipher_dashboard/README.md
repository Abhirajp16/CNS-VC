# Vigenère Cipher Dashboard

An interactive, full-stack **classical cipher dashboard** built as a college
Cryptography / Cybersecurity project. It demonstrates how four classical
ciphers work — **Vigenère**, **Additive**, **Multiplicative** and **Affine** —
encrypt, decrypt, follow every calculation step by step, explore the 26 × 26
Tabula Recta and keep a full history of operations stored in a database.

---

## Description

The Vigenère cipher uses a repeating keyword to encrypt text; the three newer
ciphers are monoalphabetic (Additive = Caesar shift, Multiplicative, and Affine
= a·x + b). This dashboard lets a student type a plaintext message and a secret
key, run the algorithm, and immediately see:

* the result,
* the repeated key aligned with the message (Vigenère),
* a per-character calculation table (letter values, formula, result),
* the Tabula Recta with the exact cells used highlighted (Vigenère),
* the **modular multiplicative inverse** when decrypting Multiplicative/Affine,
* statistics (total / encrypted / decrypted / average key length + per-cipher),
* a complete operation history stored in SQLite, tagged with the cipher name.

Everything runs locally with Flask, SQLite and plain HTML/CSS/JavaScript —
no frameworks, no cloud services.

---

## Features

* **Login / logout** with Flask sessions and hashed passwords (default `admin / admin123`)

**Vigenère cipher** (original implementation, unchanged)

* **Encryption** — `C = (P + K) mod 26`
* **Decryption** — `P = (C - K + 26) mod 26`
* **Automatic key repetition** (spaces and symbols do not consume a key character)
* **Full 26 × 26 Vigenère Tabula Recta** with live cell highlighting

**Additive / Multiplicative / Affine ciphers** (added on top)

* Dedicated page per cipher: `/cipher/additive`, `/cipher/multiplicative`, `/cipher/affine`
* Additive — `C = (P + K) mod 26`, `P = (C - K) mod 26`
* Multiplicative — `C = (P * K) mod 26`, `P = (C * K⁻¹) mod 26`
* Affine — `C = (a·P + b) mod 26`, `P = a⁻¹·(C - b) mod 26`
* **Key validation**: the multiplicative key (and the Affine `a`) must be coprime
  with 26 — `1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25`; invalid keys such as
  `2` are rejected with a clear message
* **Automatic modular inverse**, computed and displayed during decryption
* **Letter case, spaces, digits and punctuation are preserved** in the output

**Shared**

* **Step-by-step calculation table** for every character:
  `Position | Input Character | Numerical Value | Key Values | Formula | Calculated Value | Output Character`
* **Alphabet value reference** (A = 0 … Z = 25)
* **Visual encryption flow** diagram
* **Result card** with *Copy Result* and *Download Result*
* **SQLite history** — one shared table, each row tagged with the cipher name
* **Live dashboard statistics** from the database (plus a Chart.js breakdown and
  an *Operations by Cipher* breakdown)
* **Input validation** for empty messages, empty keys and invalid keys
* **Responsive dark glassmorphism UI** (desktop, laptop, tablet, mobile)
* **How It Works** educational page (advantages, limitations, worked example,
  and a section for each of the three new ciphers)

---

## Technology Stack

| Layer     | Technology                                  |
|-----------|---------------------------------------------|
| Frontend  | HTML5, CSS3, Bootstrap 5, JavaScript, Font Awesome, Chart.js |
| Backend   | Python 3, Flask                             |
| Database  | SQLite via Flask-SQLAlchemy                 |
| Auth      | Flask sessions + Werkzeug password hashing  |

Architecture:

```text
Frontend
HTML + CSS + Bootstrap + JavaScript
              ↓
          Flask API
              ↓
       Python Logic
              ↓
          SQLite
```

---

## Project Structure

```text
vigenere_cipher_dashboard/
│
├── app.py                  Flask routes, models, statistics, migration
├── ciphers.py              Additive / Multiplicative / Affine engines
├── requirements.txt
├── database.db             (created automatically on first run)
│
├── templates/
│   ├── index.html
│   ├── login.html
│   ├── dashboard.html      Vigenère (dashboard)
│   ├── ciphers.html        Additive / Multiplicative / Affine (shared)
│   ├── history.html
│   └── how_it_works.html
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       ├── script.js       shared helpers + Vigenère UI
│       └── ciphers.js      Additive / Multiplicative / Affine UI
│
├── test_e2e.py             33-test regression suite
├── test_ciphers.py         96-test suite for the three new ciphers
├── reset_history.py
└── README.md
```

---

## Installation

```bash
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

## Open

```text
http://127.0.0.1:5000
```

The database (`database.db`) and the default account are created automatically
on the first run.

---

## Default Login

```text
Username: admin
Password: admin123
```

> Passwords are stored **hashed** (Werkzeug `generate_password_hash`), never in
> plain text. Change the account for any non-demonstration use.

---

## Algorithm

### Encryption

```text
C = (P + K) mod 26
```

### Decryption

```text
P = (C - K + 26) mod 26
```

Where every letter maps to a number: `A = 0, B = 1, … Z = 25`.

### Example

```text
Plaintext:   HELLO
Key:         KEY       → repeated as KEYKE
Ciphertext:  RIJVS
```

```text
H(7) + K(10) = 17 → R
E(4)  + E(4)  =  8 → I
L(11) + Y(24) =  9 → J
L(11) + K(10) = 21 → V
O(14) + E(4)  = 18 → S
```

Spaces, digits and special characters pass through unchanged and **do not
consume a key character**:

```text
Message:       HELLO WORLD
Repeated key:  KEYKEY KEYK
```

---

## Algorithms (three added ciphers)

All three use `A = 0, B = 1, … Z = 25` and wrap with `mod 26`.

### Additive (Caesar)

```text
Encryption: C = (P + K) mod 26
Decryption: P = (C - K) mod 26
```

```text
Plaintext  HELLO   key K = 3
Ciphertext KHOOR
```

### Multiplicative

```text
Encryption: C = (P * K) mod 26
Decryption: P = (C * K⁻¹) mod 26
```

`K` must be **coprime with 26**, otherwise `K⁻¹` does not exist.

```text
Valid keys: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25
Rejected:   0, 2, 4, 6, 13, 26, ...
```

```text
Plaintext  HELLO   key K = 5
Ciphertext JUDDS
Decrypt:   5⁻¹ = 21   because 5 × 21 = 105 = 4 × 26 + 1
```

### Affine

```text
Encryption: C = (a * P + b) mod 26
Decryption: P = a⁻¹ * (C - b) mod 26
```

`a` must be coprime with 26; `b` may be any whole number.

```text
Plaintext  HELLO   a = 5, b = 8
Ciphertext RCLLA
Decrypt:   a⁻¹ = 21
```

The modular inverse is **computed automatically** and displayed while
decrypting, both in the *Modular Inverse* panel and in the `Key Values`
column of the step table.

---

## Routes

| Route                   | Method | Purpose                              |
|-------------------------|--------|--------------------------------------|
| `/`                     | GET    | Landing page                         |
| `/login`                | GET/POST | Authentication                     |
| `/logout`               | GET    | Clear the session                    |
| `/dashboard`            | GET    | Main dashboard (protected)           |
| `/encrypt` `/decrypt`   | GET    | Dashboard with the mode preselected  |
| `/history`              | GET    | Operation history (protected)        |
| `/history/delete/<id>`  | POST   | Delete one operation                 |
| `/how-it-works`         | GET    | Educational page                     |
| `/cipher/<cipher_id>`   | GET    | Additive / Multiplicative / Affine UI (protected) |
| `/api/process`          | POST   | Vigenère encrypt / decrypt + save    |
| `/api/cipher`           | POST   | Additive / Multiplicative / Affine encrypt / decrypt + save |
| `/api/statistics`       | GET    | Dashboard statistics (JSON)          |
| `/api/history`          | GET    | History as JSON                      |

`cipher_id` is one of `additive`, `multiplicative`, `affine`.

---

## Tests

```bash
# 1. start the server (keep this terminal running)
python app.py

# 2. in a second terminal
set PORT=5000
python test_e2e.py       # 33 regression tests (Vigenère, auth, history, stats)
python test_ciphers.py   # 96 tests for the three new ciphers + regression
```

Both scripts print `[PASS]` / `[FAIL]` per assertion and exit with a non-zero
status when something fails.

---

## Security Notes

* All dashboard and API routes are protected by a Flask-session login check.
* Passwords are hashed; plain passwords are never stored or displayed.
* All database access goes through SQLAlchemy (parameterized queries) — no raw SQL.
* Inputs are validated on both the client and the server (empty message, empty key,
  non-alphabetic key, length limits).
* A Flask `SECRET_KEY` signs the session cookie (`FLASK_SECRET_KEY` env variable
  can override the development default).
* CSRF tokens / HTTPS should be added before using this beyond a classroom demo.

---

## Educational Purpose

**This application is intended for educational purposes only.** The Vigenère,
Additive, Multiplicative and Affine ciphers are historically interesting and
excellent for learning, but all of them are **monoalphabetic or breakable
classical ciphers** (frequency analysis defeats them) and must **not** be used
for protecting real information.
