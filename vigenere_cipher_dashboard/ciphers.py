"""
Classical cipher engines
========================
Pure-Python implementations of the three ciphers added to the dashboard:

    * Additive       C = (P + K) mod 26
    * Multiplicative C = (P * K) mod 26
    * Affine         C = (a * P + b) mod 26

Every engine returns the *same* payload shape, so one front-end renderer can
draw the step-by-step table for all three ciphers:

    position | input_char | numeric_value | key_values |
    formula  | calculated_value | output_char

Rules shared by the three engines:
    * A = 0, B = 1, ... Z = 25
    * spaces, digits and punctuation pass through unchanged (no key applied)
    * upper / lower case is preserved in the output
    * no Flask / database imports — this module stays easy to unit test
"""

import re
from math import gcd

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Keys that have a modular multiplicative inverse modulo 26 (coprime with 26).
VALID_MULTIPLICATIVE_KEYS = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
VALID_KEYS_TEXT = ", ".join(str(k) for k in VALID_MULTIPLICATIVE_KEYS)

# Strict integer matcher: accepts "+3", "-4", "25" but rejects "3.5", "3a", "three".
_INT_RE = re.compile(r"^[+-]?[0-9]+$")


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------
def is_letter(char: str) -> bool:
    """True when the character is an ASCII letter A-Z / a-z."""
    return bool(char) and "A" <= char.upper() <= "Z"


def parse_int(raw, label: str = "Key") -> int:
    """
    Convert a key field into an int.

    Raises ValueError with a message that is shown verbatim to the user.
    """
    text = "" if raw is None else str(raw).strip()
    if not text:
        raise ValueError("Please enter a key.")
    if not _INT_RE.match(text):
        raise ValueError(f"{label} must be a whole number, e.g. 3.")
    return int(text)


def mod_inverse(a: int, modulus: int = 26):
    """Modular multiplicative inverse of a mod 26, or None when it does not exist."""
    a %= modulus
    for candidate in range(1, modulus):
        if (a * candidate) % modulus == 1:
            return candidate
    return None


def require_coprime(value: int, label: str = "Key") -> int:
    """
    Normalise a multiplicative key to 0..25 and guarantee it is coprime with 26.

    Raises ValueError listing the valid keys when the inverse does not exist.
    """
    normalised = value % 26
    if gcd(normalised, 26) != 1:
        raise ValueError(
            f"{label} must be coprime with 26. Valid keys: {VALID_KEYS_TEXT}."
        )
    return normalised


def _passthrough_step(position: int, char: str) -> dict:
    """Step row for a character that is not a letter (no key is applied)."""
    return {
        "position": position,
        "input_char": char,
        "numeric_value": "-",
        "key_values": "-",
        "formula": "no shift (non-letter)",
        "calculated_value": "-",
        "output_char": char,
    }


def _letter_step(position: int, char: str, value: int, key_values: str,
                 formula: str, calculated: int, output_char: str) -> dict:
    return {
        "position": position,
        "input_char": char,
        "numeric_value": value,
        "key_values": key_values,
        "formula": formula,
        "calculated_value": calculated,
        "output_char": output_char,
    }


def _restore_case(letter: str, original: str) -> str:
    """Keep the upper / lower case of the original character."""
    return letter.lower() if original.islower() else letter.upper()


# --------------------------------------------------------------------------
# 1. Additive cipher (Caesar)
# --------------------------------------------------------------------------
def run_additive(message: str, key, mode: str) -> dict:
    """
    Encryption : C = (P + K) mod 26
    Decryption : P = (C - K) mod 26
    """
    k = parse_int(key, "Numerical Key (K)") % 26
    enc_formula_text = "C = (P + K) mod 26"
    dec_formula_text = "P = (C - K) mod 26"

    result_chars = []
    steps = []

    for position, char in enumerate(message, start=1):
        if not is_letter(char):
            result_chars.append(char)
            steps.append(_passthrough_step(position, char))
            continue

        value = ord(char.upper()) - 65

        if mode == "encrypt":
            calculated = (value + k) % 26
            formula = f"({value}+{k})%26"
        else:
            calculated = (value - k) % 26
            formula = f"({value}-{k})%26"

        output = _restore_case(ALPHABET[calculated], char)
        result_chars.append(output)
        steps.append(
            _letter_step(position, char, value, f"K = {k}", formula,
                         calculated, output)
        )

    return {
        "result": "".join(result_chars),
        "steps": steps,
        "key_display": f"K = {k}",
        "inverse": None,
        "inverse_note": "",
        "enc_formula": enc_formula_text,
        "dec_formula": dec_formula_text,
    }


# --------------------------------------------------------------------------
# 2. Multiplicative cipher
# --------------------------------------------------------------------------
def run_multiplicative(message: str, key, mode: str) -> dict:
    """
    Encryption : C = (P * K) mod 26
    Decryption : P = (C * K_inverse) mod 26
    """
    k = require_coprime(parse_int(key, "Multiplicative Key (K)"), "Multiplicative Key (K)")
    inverse = mod_inverse(k)
    enc_formula_text = "C = (P * K) mod 26"
    dec_formula_text = "P = (C * K_inverse) mod 26"

    key_values = f"K = {k}"
    if mode == "decrypt":
        key_values += f", K\u207B\u00B9 = {inverse}"

    result_chars = []
    steps = []

    for position, char in enumerate(message, start=1):
        if not is_letter(char):
            result_chars.append(char)
            steps.append(_passthrough_step(position, char))
            continue

        value = ord(char.upper()) - 65

        if mode == "encrypt":
            calculated = (value * k) % 26
            formula = f"({value}*{k})%26"
        else:
            calculated = (value * inverse) % 26
            formula = f"({value}*{inverse})%26"

        output = _restore_case(ALPHABET[calculated], char)
        result_chars.append(output)
        steps.append(
            _letter_step(position, char, value, key_values, formula,
                         calculated, output)
        )

    inverse_note = ""
    if mode == "decrypt":
        inverse_note = f"K\u207B\u00B9 = {inverse} because {k} \u00D7 {inverse} = 1 (mod 26)"

    return {
        "result": "".join(result_chars),
        "steps": steps,
        "key_display": f"K = {k}",
        "inverse": inverse,
        "inverse_note": inverse_note,
        "enc_formula": enc_formula_text,
        "dec_formula": dec_formula_text,
    }


# --------------------------------------------------------------------------
# 3. Affine cipher
# --------------------------------------------------------------------------
def run_affine(message: str, key_a, key_b, mode: str) -> dict:
    """
    Encryption : C = (a * P + b) mod 26
    Decryption : P = (a_inverse * (C - b)) mod 26
    """
    a = require_coprime(parse_int(key_a, "Multiplicative Key (a)"), "Multiplicative Key (a)")
    b = parse_int(key_b, "Additive Key (b)") % 26
    a_inverse = mod_inverse(a)

    enc_formula_text = "C = (a * P + b) mod 26"
    dec_formula_text = "P = (a_inverse * (C - b)) mod 26"

    key_values = f"a = {a}, b = {b}"
    if mode == "decrypt":
        key_values += f", a\u207B\u00B9 = {a_inverse}"

    result_chars = []
    steps = []

    for position, char in enumerate(message, start=1):
        if not is_letter(char):
            result_chars.append(char)
            steps.append(_passthrough_step(position, char))
            continue

        value = ord(char.upper()) - 65

        if mode == "encrypt":
            calculated = (a * value + b) % 26
            formula = f"({a}*{value}+{b})%26"
        else:
            calculated = (a_inverse * (value - b)) % 26
            formula = f"({a_inverse}*({value}-{b}))%26"

        output = _restore_case(ALPHABET[calculated], char)
        result_chars.append(output)
        steps.append(
            _letter_step(position, char, value, key_values, formula,
                         calculated, output)
        )

    inverse_note = ""
    if mode == "decrypt":
        inverse_note = f"a\u207B\u00B9 = {a_inverse} because {a} \u00D7 {a_inverse} = 1 (mod 26)"

    return {
        "result": "".join(result_chars),
        "steps": steps,
        "key_display": f"a = {a}, b = {b}",
        "inverse": a_inverse,
        "inverse_note": inverse_note,
        "enc_formula": enc_formula_text,
        "dec_formula": dec_formula_text,
    }


# --------------------------------------------------------------------------
# Registry used by the Flask routes / templates
# --------------------------------------------------------------------------
CIPHER_CONFIGS = {
    "additive": {
        "id": "additive",
        "name": "Additive Cipher",
        "short": "Additive",
        "tagline": "Monoalphabetic Shift Cipher (Caesar)",
        "icon": "fa-plus",
        "description": (
            "Every letter is shifted by the same fixed number K. "
            "The Additive cipher (Caesar cipher) uses a single numerical key "
            "for the whole message."
        ),
        "enc_formula": "C = (P + K) mod 26",
        "dec_formula": "P = (C - K) mod 26",
        "has_inverse": False,
        "key_fields": [
            {
                "name": "k",
                "label": "Numerical Key (K)",
                "placeholder": "e.g. 3",
                "help": "A whole number. 0 – 25 are the classic values (other integers wrap around with mod 26).",
            }
        ],
        "valid_keys_note": "Any whole number — 0 to 25 for the classic key space.",
    },
    "multiplicative": {
        "id": "multiplicative",
        "name": "Multiplicative Cipher",
        "short": "Multiplicative",
        "tagline": "Modular Multiplication Cipher",
        "icon": "fa-xmark",
        "description": (
            "Every letter value is multiplied by K modulo 26. The key must be "
            "coprime with 26 so that a modular inverse exists for decryption."
        ),
        "enc_formula": "C = (P * K) mod 26",
        "dec_formula": "P = (C * K_inverse) mod 26",
        "has_inverse": True,
        "key_fields": [
            {
                "name": "k",
                "label": "Multiplicative Key (K)",
                "placeholder": "e.g. 5",
                "help": f"Must be coprime with 26. Valid keys: {VALID_KEYS_TEXT}.",
            }
        ],
        "valid_keys_note": f"Coprime with 26: {VALID_KEYS_TEXT}.",
    },
    "affine": {
        "id": "affine",
        "name": "Affine Cipher",
        "short": "Affine",
        "tagline": "Linear (a·x + b) Cipher",
        "icon": "fa-calculator",
        "description": (
            "The Affine cipher combines the other two: multiplication by a "
            "followed by an addition of b. Decryption needs the modular inverse of a."
        ),
        "enc_formula": "C = (a * P + b) mod 26",
        "dec_formula": "P = (a_inverse * (C - b)) mod 26",
        "has_inverse": True,
        "key_fields": [
            {
                "name": "a",
                "label": "Multiplicative Key (a)",
                "placeholder": "e.g. 5",
                "help": f"Must be coprime with 26. Valid values: {VALID_KEYS_TEXT}.",
            },
            {
                "name": "b",
                "label": "Additive Key (b)",
                "placeholder": "e.g. 8",
                "help": "Any whole number — 0 – 25 for the classic key space.",
            },
        ],
        "valid_keys_note": f"a coprime with 26: {VALID_KEYS_TEXT} · b any whole number.",
    },
}


def run_classical(cipher_id: str, message: str, keys: dict, mode: str) -> dict:
    """Dispatch to one of the three engines and validate the mode."""
    if mode not in ("encrypt", "decrypt"):
        raise ValueError("Invalid operation mode.")
    if not message:
        raise ValueError("Please enter a message.")

    keys = keys or {}

    if cipher_id == "additive":
        return run_additive(message, keys.get("k"), mode)
    if cipher_id == "multiplicative":
        return run_multiplicative(message, keys.get("k"), mode)
    if cipher_id == "affine":
        return run_affine(message, keys.get("a"), keys.get("b"), mode)

    raise ValueError("Unknown cipher.")
