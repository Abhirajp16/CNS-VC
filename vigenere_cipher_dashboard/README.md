# Vigenère Cipher Dashboard

An interactive, full-stack **Vigenère Cipher Dashboard** built as a college
Cryptography / Cybersecurity project. It demonstrates how the classical
polyalphabetic substitution cipher works — encrypt, decrypt, follow every
calculation step by step, explore the 26 × 26 Tabula Recta and keep a full
history of operations stored in a database.

---

## Description

The Vigenère cipher uses a repeating keyword to encrypt text. This dashboard
lets a student type a plaintext message and a secret key, run the algorithm,
and immediately see:

* the result,
* the repeated key aligned with the message,
* a per-character calculation table (letter values, formula, result),
* the Tabula Recta with the exact cells used highlighted,
* statistics (total / encrypted / decrypted / average key length),
* a complete operation history stored in SQLite.

Everything runs locally with Flask, SQLite and plain HTML/CSS/JavaScript —
no frameworks, no cloud services.

---

## Features

* **Login / logout** with Flask sessions and hashed passwords (default `admin / admin123`)
* **Encryption** — `C = (P + K) mod 26`
* **Decryption** — `P = (C - K + 26) mod 26`
* **Automatic key repetition** (spaces and symbols do not consume a key character)
* **Step-by-step calculation table** for every character
* **Full 26 × 26 Vigenère Tabula Recta** with live cell highlighting
* **Alphabet value reference** (A = 0 … Z = 25)
* **Visual encryption flow** diagram
* **Result card** with *Copy Result* and *Download Result* (`vigenere_result.txt`)
* **SQLite history** — view, inspect and delete past operations
* **Live dashboard statistics** from the database (plus a Chart.js breakdown)
* **Input validation** for empty messages, empty keys and non-alphabetic keys
* **Responsive dark glassmorphism UI** (desktop, laptop, tablet, mobile)
* **How It Works** educational page (advantages, limitations, worked example)

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
├── app.py
├── requirements.txt
├── database.db          (created automatically on first run)
│
├── templates/
│   ├── index.html
│   ├── login.html
│   ├── dashboard.html
│   ├── history.html
│   └── how_it_works.html
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── script.js
│
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
| `/api/process`          | POST   | Encrypt / decrypt + save to SQLite   |
| `/api/statistics`       | GET    | Dashboard statistics (JSON)          |
| `/api/history`          | GET    | History as JSON                      |

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

**This application is intended for educational purposes only.** The Vigenère
cipher is historically interesting and excellent for learning, but it is
vulnerable to cryptanalysis (frequency analysis of repeating key patterns) and
must **not** be used for protecting real information.
