"""
Vigenere Cipher Dashboard
=========================
A full-stack Flask application that demonstrates the Vigenere cipher
(polyalphabetic substitution cipher) with step-by-step calculations,
a visual Tabula Recta, history storage and dashboard statistics.

Stack: Flask + Flask-SQLAlchemy + SQLite + Bootstrap 5 + JavaScript
"""

import os
from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    flash,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# --------------------------------------------------------------------------
# App configuration
# --------------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "vigenere-dashboard-secret-key-change-in-production")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "database.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


# --------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------
class User(db.Model):
    """Application user (passwords are stored hashed)."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def __repr__(self) -> str:
        return f"<User {self.username}>"


class Operation(db.Model):
    """A stored encryption / decryption operation."""

    __tablename__ = "operations"

    id = db.Column(db.Integer, primary_key=True)
    operation_type = db.Column(db.String(20), nullable=False)  # Encryption / Decryption
    input_text = db.Column(db.Text, nullable=False)
    key = db.Column(db.String(255), nullable=False)
    result = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def formatted_date(self) -> str:
        return self.created_at.strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "operation_type": self.operation_type,
            "input_text": self.input_text,
            "key": self.key,
            "result": self.result,
            "created_at": self.formatted_date,
        }

    def __repr__(self) -> str:
        return f"<Operation {self.id} {self.operation_type}>"


# --------------------------------------------------------------------------
# Auth helpers
# --------------------------------------------------------------------------
def login_required(view):
    """Protect dashboard / history / API routes."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "Authentication required."}), 401
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


# --------------------------------------------------------------------------
# Vigenere cipher engine (server side)
# --------------------------------------------------------------------------
def is_letter(char: str) -> bool:
    """True when the character is an ASCII letter A-Z / a-z."""
    return "A" <= char.upper() <= "Z"


def clean_key(key: str) -> str:
    """Keep only alphabetic characters of the key, upper-cased."""
    return "".join(c.upper() for c in key if is_letter(c))


def run_cipher(message: str, key: str, mode: str):
    """
    Encrypt ('encrypt') or decrypt ('decrypt') a message with a Vigenere key.

    Encryption : C = (P + K) mod 26
    Decryption : P = (C - K + 26) mod 26

    Spaces, digits and special characters are copied through unchanged and
    do NOT consume a key character.

    Returns (result, repeated_key, steps, highlights).
    """
    key_chars = list(clean_key(key))
    if not key_chars:
        raise ValueError("Key must contain at least one alphabetic character.")
    if not message:
        raise ValueError("Please enter a message.")
    if mode not in ("encrypt", "decrypt"):
        raise ValueError("Invalid operation mode.")

    result_chars = []
    repeated_key_chars = []
    steps = []
    highlights = []
    key_index = 0  # advances only on alphabetic characters

    for position, char in enumerate(message, start=1):
        upper = char.upper()

        if not is_letter(char):
            # Spaces / digits / symbols keep their value, consume no key.
            result_chars.append(char)
            repeated_key_chars.append(" ")
            steps.append(
                {
                    "position": position,
                    "text": char,
                    "key": "-",
                    "text_value": "-",
                    "key_value": "-",
                    "formula": "no key consumed",
                    "result": char,
                }
            )
            continue

        key_char = key_chars[key_index % len(key_chars)]
        text_value = ord(upper) - 65          # A = 0 ... Z = 25
        key_value = ord(key_char) - 65

        if mode == "encrypt":
            result_value = (text_value + key_value) % 26
            formula = f"({text_value}+{key_value})%26"
        else:
            result_value = (text_value - key_value + 26) % 26
            formula = f"({text_value}-{key_value}+26)%26"

        result_char = ALPHABET[result_value]

        result_chars.append(result_char)
        repeated_key_chars.append(key_char)
        steps.append(
            {
                "position": position,
                "text": upper,
                "key": key_char,
                "text_value": text_value,
                "key_value": key_value,
                "formula": formula,
                "result": result_char,
            }
        )

        # Tabula Recta highlight: row = key letter, column = plain letter,
        # the intersecting cell is the cipher letter.
        plain_value = text_value if mode == "encrypt" else result_value
        highlights.append(
            {
                "row": key_value,       # key letter (row header)
                "col": plain_value,     # plain letter (column header)
                "cell": result_char,
                "position": position,
            }
        )

        key_index += 1

    return "".join(result_chars), "".join(repeated_key_chars), steps, highlights


def get_statistics() -> dict:
    """Aggregate dashboard statistics from the operations table."""
    total = Operation.query.count()
    encrypted = Operation.query.filter_by(operation_type="Encryption").count()
    decrypted = Operation.query.filter_by(operation_type="Decryption").count()

    key_lengths = [len(clean_key(op.key)) for op in Operation.query.all()]
    avg_key_length = round(sum(key_lengths) / len(key_lengths)) if key_lengths else 0

    return {
        "total": total,
        "encrypted": encrypted,
        "decrypted": decrypted,
        "avg_key_length": avg_key_length,
    }


# --------------------------------------------------------------------------
# Routes - pages
# --------------------------------------------------------------------------
@app.route("/")
def index():
    """Landing page."""
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Simple username / password login (Flask session based)."""
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        wants_json = request.is_json or request.accept_mimetypes.best == "application/json"

        if not username or not password:
            message = "Please enter both username and password."
            if wants_json:
                return jsonify({"ok": False, "error": message}), 400
            flash(message, "danger")
            return render_template("login.html"), 400

        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            message = "Invalid username or password."
            if wants_json:
                return jsonify({"ok": False, "error": message}), 401
            flash(message, "danger")
            return render_template("login.html"), 401

        session["user_id"] = user.id
        session["username"] = user.username

        if wants_json:
            return jsonify({"ok": True, "username": user.username,
                            "redirect": url_for("dashboard")})

        flash(f"Welcome back, {user.username}!", "success")

        next_url = request.args.get("next")
        if next_url and next_url.startswith("/") and not next_url.startswith("//"):
            return redirect(next_url)
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    """Clear the session."""
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", mode="encrypt")


@app.route("/encrypt")
@login_required
def encrypt_page():
    return render_template("dashboard.html", mode="encrypt")


@app.route("/decrypt")
@login_required
def decrypt_page():
    return render_template("dashboard.html", mode="decrypt")


@app.route("/history")
@login_required
def history():
    operations = Operation.query.order_by(Operation.created_at.desc(), Operation.id.desc()).all()
    stats = get_statistics()
    return render_template("history.html", operations=operations, stats=stats)


@app.route("/history/delete/<int:op_id>", methods=["POST"])
@login_required
def delete_operation(op_id):
    """Delete a single stored operation."""
    operation = db.session.get(Operation, op_id)
    if operation is None:
        message = "Operation not found."
        if request.is_json:
            return jsonify({"ok": False, "error": message}), 404
        flash(message, "warning")
        return redirect(url_for("history"))

    db.session.delete(operation)
    db.session.commit()
    flash("Operation deleted.", "success")

    if request.is_json:
        return jsonify({"ok": True, "statistics": get_statistics()})
    return redirect(url_for("history"))


@app.route("/how-it-works")
def how_it_works():
    return render_template("how_it_works.html")


# --------------------------------------------------------------------------
# Routes - JSON APIs
# --------------------------------------------------------------------------
@app.route("/api/process", methods=["POST"])
@login_required
def api_process():
    """
    Encrypt or decrypt a message and store the operation.

    Body (JSON): { "mode": "encrypt" | "decrypt", "message": "...", "key": "..." }
    """
    data = request.get_json(silent=True) or {}

    mode = str(data.get("mode", "")).strip().lower()
    message = data.get("message")
    key = data.get("key")

    if message is None or key is None:
        return jsonify({"ok": False, "error": "Please enter a message and a key."}), 400

    message = str(message)
    key = str(key)

    # ---------------- validation ----------------
    if not message.strip():
        return jsonify({"ok": False, "error": "Please enter a message.", "field": "message"}), 400
    if not key.strip():
        return jsonify({"ok": False, "error": "Please enter a key.", "field": "key"}), 400
    if not clean_key(key):
        return jsonify(
            {"ok": False, "error": "Key must contain at least one alphabetic character.", "field": "key"}
        ), 400
    if mode not in ("encrypt", "decrypt"):
        return jsonify({"ok": False, "error": "Invalid operation mode."}), 400
    if len(message) > 5000 or len(key) > 200:
        return jsonify({"ok": False, "error": "Input is too long (max 5000 characters)."}), 400

    try:
        result, repeated_key, steps, highlights = run_cipher(message, key, mode)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    operation_type = "Encryption" if mode == "encrypt" else "Decryption"
    operation = Operation(
        operation_type=operation_type,
        input_text=message,
        key=clean_key(key),
        result=result,
    )
    db.session.add(operation)
    db.session.commit()

    return jsonify(
        {
            "ok": True,
            "mode": mode,
            "operation_type": operation_type,
            "message": message,
            "input_upper": message.upper(),
            "key": clean_key(key),
            "result": result,
            "repeated_key": repeated_key,
            "steps": steps,
            "highlights": highlights,
            "id": operation.id,
            "statistics": get_statistics(),
        }
    )


@app.route("/api/statistics")
@login_required
def api_statistics():
    return jsonify({"ok": True, "statistics": get_statistics()})


@app.route("/api/history")
@login_required
def api_history():
    operations = Operation.query.order_by(Operation.created_at.desc(), Operation.id.desc()).all()
    return jsonify({"ok": True, "operations": [op.to_dict() for op in operations]})


# --------------------------------------------------------------------------
# Bootstrapping
# --------------------------------------------------------------------------
def seed_database():
    """Create tables and the default demo account (admin / admin123)."""
    with app.app_context():
        db.create_all()
        if User.query.filter_by(username="admin").first() is None:
            admin = User(username="admin")
            admin.set_password("admin123")
            db.session.add(admin)
            db.session.commit()


seed_database()


if __name__ == "__main__":
    # Default port 5000; override with e.g. `set PORT=5001` if 5000 is in use.
    port = int(os.environ.get("PORT", "5000"))
    app.run(debug=True, host="127.0.0.1", port=port)
