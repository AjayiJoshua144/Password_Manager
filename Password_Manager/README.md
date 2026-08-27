# 🔐 LockDown — Student Password Manager
**Author:** Ajayi Joshua Abayomi | Babcock University | 300L IT
**Stack:** Python · Flask · SQLite · AES-GCM · PBKDF2 · bcrypt

---

## 📌 What This Does
A web-based password manager that stores your credentials securely using real-world encryption. Built at student (300L) level — every line is commented to explain what and why.

| Feature | How |
|---|---|
| User Registration | bcrypt salted hash of master password |
| Login Auth | bcrypt.checkpw() — never compare plain text |
| Vault Encryption | AES-256-GCM per entry |
| Key Derivation | PBKDF2-SHA256, 480,000 iterations |
| Password Generator | Python `secrets` module (cryptographic RNG) |
| Clipboard Safety | Auto-clears clipboard after 30 seconds |
| Auto-hide | Revealed passwords hide automatically after 30s |

---

## 📁 File Structure
```
passmanager/
├── app.py          ← Flask routes (main entry point)
├── crypto.py       ← AES-GCM encrypt/decrypt + PBKDF2 key derivation
├── database.py     ← SQLite setup + all DB queries
├── requirements.txt
├── templates/
│   ├── base.html   ← Shared layout, nav, flash messages
│   ├── index.html  ← Landing page
│   ├── register.html
│   ├── login.html
│   └── vault.html  ← Main CRUD dashboard
└── README.md
```

---

## ⚙️ How to Run

### Step 1 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 2 — Run the app
```bash
python app.py
```

### Step 3 — Open browser
```
http://127.0.0.1:5000
```

---

## 🧠 Key Concepts Explained (for study)

### Why two different hashing operations?
| Purpose | Algorithm | Stored In |
|---|---|---|
| Login check | bcrypt | DB (users.password_hash) |
| Vault key | PBKDF2 → AES key | Session only (never stored) |

### Encryption Flow
```
User types master password
       ↓
PBKDF2 (480,000 rounds + salt) → 256-bit key
       ↓
AES-GCM (key + random nonce) → encrypted blob
       ↓
base64 encoded → stored in DB
```

### Decryption Flow
```
User logs in → PBKDF2 re-derives same key
       ↓
Clicks "Reveal" → fetch() to server
       ↓
Server decrypts with session key → returns plain text
       ↓
Auto-hides after 30 seconds
```

---

## ⚠️ Learning Note
This is a student project — for production use you would also add:
- HTTPS (TLS)
- CSRF tokens on all forms  
- Rate limiting on login
- Multi-factor authentication (TOTP)

---
© 2026 Ajayi Joshua Abayomi | Babcock University
