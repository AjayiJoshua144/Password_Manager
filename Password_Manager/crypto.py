# =============================================================
#  crypto.py  —  Encryption helpers for the Password Manager
#  Author : Ajayi Joshua Abayomi | Babcock University | 300L
#  Tools  : Python cryptography library, AES-GCM, PBKDF2
# =============================================================
#
#  CONCEPTS USED (read this first!):
#  ─────────────────────────────────
#  1. PBKDF2   → Turns a weak master password into a strong 256-bit key.
#                (Password-Based Key Derivation Function 2)
#               "Stretches" the password by hashing it 480,000 times.
#
#  2. AES-GCM  → Encrypts the stored password entry.
#                AES  = Advanced Encryption Standard (very strong cipher)
#                GCM  = Galois/Counter Mode (also checks data wasn't tampered)
#
#  3. SALT     → Random bytes added before hashing so two identical
#                master passwords produce DIFFERENT keys/hashes.
#
#  4. NONCE    → A random number used ONCE per encryption.
#                Stops attackers from comparing two ciphertexts.
#
#  Flow:
#    Master Password  ─ PBKDF2 ─ Encryption Key
#    Encryption Key   ─ AES-GCM ─  Encrypted vault entry  (stored in DB)
#    Encrypted entry  ─ AES-GCM ─  Plain-text password    (shown to user)
# =============================================================

import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives          import hashes
from cryptography.hazmat.primitives.ciphers  import Cipher, algorithms, modes
from cryptography.hazmat.backends            import default_backend
from cryptography.exceptions                 import InvalidTag


# ── CONSTANTS ────────────────────────────────────────────────
SALT_SIZE    = 16    # bytes — random salt for key derivation
NONCE_SIZE   = 12    # bytes — AES-GCM standard nonce length
KEY_SIZE     = 32    # bytes — 256-bit AES key
PBKDF2_ITERS = 480_000  # NIST recommended minimum (2023)


# ── 1. GENERATE A RANDOM SALT ────────────────────────────────
def generate_salt() -> bytes:
    """
    Returns 16 random bytes.
    Call this ONCE per user at registration and save it in the DB.
    The same salt must be used every time we derive that user's key.
    """
    return os.urandom(SALT_SIZE)


# ── 2. DERIVE AN ENCRYPTION KEY FROM THE MASTER PASSWORD ─────
def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Takes the user's master password (plain text) + their saved salt
    and produces a 256-bit (32-byte) encryption key using PBKDF2-SHA256.

    Why not use the password directly as a key?
      → Passwords are short and guessable.
      → PBKDF2 makes brute-force attacks extremely slow.
    """
    # Encode the password string to bytes (UTF-8)
    password_bytes = master_password.encode("utf-8")

    kdf = PBKDF2HMAC(
        algorithm  = hashes.SHA256(),   # Hashing algorithm
        length     = KEY_SIZE,           # Output key length: 32 bytes
        salt       = salt,               # The user's unique salt
        iterations = PBKDF2_ITERS,       # How many times to hash
        backend    = default_backend()
    )

    return kdf.derive(password_bytes)   # Returns raw 32-byte key


# ── 3. ENCRYPT A PASSWORD ENTRY ──────────────────────────────
def encrypt(plain_text: str, key: bytes) -> str:
    """
    Encrypts a plain-text string using AES-GCM.

    Returns a single base64 string in the format:
        nonce (12 bytes) + ciphertext + tag (16 bytes)

    This combined blob is what gets stored in the database.
    The nonce is NOT secret — it just needs to be unique each time.
    """
    # Step 1: Generate a fresh random nonce for this encryption
    nonce = os.urandom(NONCE_SIZE)

    # Step 2: Create the AES-GCM cipher with our key and nonce
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    # Step 3: Encrypt the plain text
    plain_bytes  = plain_text.encode("utf-8")
    ciphertext   = encryptor.update(plain_bytes) + encryptor.finalize()

    # Step 4: GCM produces an authentication "tag" — proves data wasn't modified
    tag = encryptor.tag  # 16 bytes

    # Step 5: Join nonce + ciphertext + tag, then base64-encode for DB storage
    combined = nonce + ciphertext + tag
    return base64.b64encode(combined).decode("utf-8")


# ── 4. DECRYPT A PASSWORD ENTRY ──────────────────────────────
def decrypt(encrypted_blob: str, key: bytes) -> str:
    """
    Reverses the encrypt() function.
    Raises ValueError if the key is wrong or data was tampered with.
    """
    # Step 1: Decode from base64 back to raw bytes
    combined = base64.b64decode(encrypted_blob.encode("utf-8"))

    # Step 2: Split out the nonce, ciphertext, and tag
    nonce      = combined[:NONCE_SIZE]
    tag        = combined[-16:]               # Last 16 bytes = GCM tag
    ciphertext = combined[NONCE_SIZE:-16]     # Everything in between

    # Step 3: Re-create the cipher (same key + same nonce = same keystream)
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),   # tag is passed so GCM can verify integrity
        backend=default_backend()
    )
    decryptor = cipher.decryptor()

    try:
        # Step 4: Decrypt — GCM also verifies the tag here
        plain_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        return plain_bytes.decode("utf-8")

    except InvalidTag:
        # This means either the key is wrong OR the data was modified
        raise ValueError("Decryption failed: wrong master password or corrupted data.")


# ── 5. WIPE A SENSITIVE VARIABLE FROM MEMORY ─────────────────
def clear_secret(secret: bytearray) -> None:
    """
    Overwrites a bytearray in memory with zeros.
    Use this after you're done with a key or plain-text password
    so it doesn't linger in RAM.

    Note: Python strings are immutable so we use bytearray for secrets
          when we want to be able to wipe them.
    """
    for i in range(len(secret)):
        secret[i] = 0
