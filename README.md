# 🔐 SecureVault — End-to-End Encrypted Communication Platform

> **Military-grade AES-256-GCM end-to-end encryption for confidential messages and images with a zero-knowledge server architecture and enterprise cybersecurity interface.**

---

## 📋 Table of Contents
- [Overview](#-overview)
- [Key Features](#-key-features)
- [Cryptographic Architecture](#-cryptographic-architecture)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Running the Application](#running-the-application)
- [API Reference](#-api-reference)
- [Security & Zero-Knowledge Model](#-security--zero-knowledge-model)
- [UI/UX Design System](#-uiux-design-system)

---

## 🌟 Overview

**SecureVault** is an enterprise-grade End-to-End Encrypted (E2EE) messaging and image exchange application designed to guarantee total privacy and confidentiality. All encryption and decryption operations occur strictly inside the user's web browser using standard Web Crypto APIs (`SubtleCrypto`). The server acts purely as a zero-knowledge routing and storage layer—storing only opaque ciphertext blobs and metadata, and never having access to plaintext keys, passwords, or decrypted content.

---

## ✨ Key Features

- 💬 **Client-Side Encrypted Messaging:** Messages are encrypted locally using AES-256-GCM before transmission.
- 🖼️ **Encrypted Image Sharing:** High-resolution image files (JPEG, PNG, WebP up to 25MB) encrypted client-side with authenticated data before upload.
- 🛡️ **AEAD Tamper Detection:** Authenticated Encryption with Associated Data (AEAD) ensures any byte-level tampering or ciphertext alteration is detected and rejected.
- 🔑 **Strong Key Derivation:** 100,000-iteration PBKDF2-SHA-256 with unique 128-bit cryptographic salts per operation.
- 👥 **Recipients & Transfer Management:** Register peers, send transfer requests, and manage access authorizations in real time.
- 📊 **Security Dashboard & Audit Log:** Real-time visibility into cryptographic configurations, architecture overview, and audit events.
- 🎨 **Enterprise UI/UX:** Sleek dark navy (`#0B1220`) theme with crisp typography, subtle slate borders, and responsive desktop/mobile ergonomics.

---

## 🔐 Cryptographic Architecture

```
+-------------------------------------------------------------------------+
|                              YOUR BROWSER                               |
|                                                                         |
|  [ Plaintext Message / Image ]                                          |
|                |                                                        |
|                v                                                        |
|  [ PBKDF2-SHA-256 Key Derivation ] <--- (User Passphrase + 128-bit Salt)|
|                |                                                        |
|                v                                                        |
|  [ AES-256-GCM Encryptor ] <----------- (96-bit Unique Nonce / IV)      |
|                |                                                        |
|                v                                                        |
|  [ Ciphertext + 128-bit Auth Tag + Salt + IV ]                          |
+-------------------------------------------------------------------------+
                                 |
                                 | HTTPS / TLS (Encrypted Transport)
                                 v
+-------------------------------------------------------------------------+
|                          ZERO-KNOWLEDGE SERVER                          |
|                                                                         |
|  - Stores Opaque Ciphertext Blobs & Metadata                            |
|  - Hashes Passwords with Argon2id                                       |
|  - CANNOT read or decrypt messages or images                            |
+-------------------------------------------------------------------------+
                                 |
                                 | HTTPS / TLS (Encrypted Transport)
                                 v
+-------------------------------------------------------------------------+
|                            RECIPIENT BROWSER                            |
|                                                                         |
|  [ Retrieve Ciphertext + Tag + Salt + IV ]                              |
|                |                                                        |
|                v                                                        |
|  [ PBKDF2-SHA-256 Key Derivation ] <--- (Matching Shared Passphrase)    |
|                |                                                        |
|                v                                                        |
|  [ AES-256-GCM Decryptor & Tag Verifier ]                               |
|                |                                                        |
|                v                                                        |
|  [ Authenticated Plaintext Output ]                                     |
+-------------------------------------------------------------------------+
```

### Cryptographic Parameters
| Parameter | Specification | Purpose |
| :--- | :--- | :--- |
| **Symmetric Cipher** | `AES-256-GCM` | Authenticated encryption for data confidentiality & integrity |
| **Key Size** | 256 bits (32 bytes) | High security margin |
| **Authentication Tag** | 128 bits (16 bytes) | AEAD tamper resistance |
| **Key Derivation** | `PBKDF2-SHA-256` | Password-based key derivation from shared passphrase |
| **PBKDF2 Iterations** | 100,000 rounds | Protection against brute-force / GPU dictionary attacks |
| **Nonce / IV** | 96 bits (12 bytes) | Fresh cryptographically random IV per encryption operation |
| **Salt** | 128 bits (16 bytes) | Fresh cryptographically random salt per operation |
| **Random Source** | `window.crypto.getRandomValues` | OS CSPRNG |
| **Server Auth** | `Argon2id` | State-of-the-art server-side password hashing |

---

## 🛠 Tech Stack

### Frontend
- **HTML5 & Vanilla JavaScript (ES6+):** Modular client-side architecture without bloated framework dependencies.
- **Web Crypto API:** Hardware-accelerated native browser cryptography (`crypto.subtle`).
- **Vanilla CSS:** Custom enterprise design system with responsive flexbox/grid and mobile touch ergonomics.

### Backend
- **Python 3.10+ / Flask:** Lightweight RESTful API server.
- **SQLAlchemy 2.0:** Relational ORM handling users, messages, recipient transfers, and audit logs.
- **Argon2-cffi:** Modern password hashing standard recommended by OWASP.
- **SQLite:** Server database stored with automated isolated local app data provisioning.

---

## 📂 Project Structure

```
Message and Image ED/
│
├── backend/
│   ├── app.py                  # Flask API server, routes, and SQLAlchemy models
│   └── requirements.txt        # Backend dependencies
│
├── frontend/
│   ├── index.html              # Single Page Application (SPA) structure
│   ├── css/
│   │   └── style.css           # Enterprise cybersecurity UI stylesheet
│   └── js/
│       ├── app.js              # SPA router, UI event bindings, and particle canvas
│       ├── auth.js             # Authentication & session token manager
│       ├── crypto.js           # Client-side WebCrypto AES-GCM & PBKDF2 logic
│       ├── images.js           # Image encryption, upload, and local decryption
│       ├── messages.js         # Message encryption, compose, and inbox workflows
│       └── recipients.js       # Recipient discovery & transfer authorization
│
├── prds/
│   └── Professional UI&UX Requirements.md  # UI/UX Specification document
│
├── run.py                      # Application launcher / local dev server
└── README.md                   # Project documentation
```

---

## 🚀 Getting Started

### Prerequisites
- **Python 3.10** or higher installed on your system.
- A modern web browser supporting the **Web Cryptography API** (Chrome, Firefox, Edge, Safari, Brave).

### Installation

1. Clone or download the repository to your local machine:
   ```bash
   cd "Message and Image ED"
   ```

2. Install the backend Python dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```

### Running the Application

1. Start the SecureVault server:
   ```bash
   python run.py
   ```

2. Open your browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

3. Register a new user account or log in with your credentials to start exchanging encrypted messages and files.

---

## 📡 API Reference

### Authentication
- `POST /api/register` — Register a new account (hashes password with Argon2id).
- `POST /api/login` — Authenticate and receive a session bearer token.
- `POST /api/logout` — Invalidate user session.
- `GET /api/me` — Retrieve current authenticated user profile.

### Messages
- `POST /api/messages` — Send an encrypted message ciphertext blob to a recipient.
- `GET /api/messages/inbox` — Retrieve incoming encrypted messages for current user.
- `GET /api/messages/sent` — Retrieve outgoing encrypted messages sent by current user.
- `DELETE /api/messages/<id>` — Delete a message record.

### Encrypted Images
- `POST /api/images` — Upload an encrypted image blob.
- `GET /api/images` — List encrypted image records.
- `GET /api/images/<id>/download` — Download ciphertext blob for browser decryption.
- `DELETE /api/images/<id>` — Delete an image record.

### Recipients & Transfers
- `GET /api/recipients` — Search and list registered recipients.
- `POST /api/transfers/request` — Request transfer access to a recipient.
- `POST /api/transfers/<id>/respond` — Accept or decline an incoming transfer authorization.

### Security & Audit
- `GET /api/security/specs` — Retrieve system cryptographic configuration metadata.
- `GET /api/audit-logs` — Retrieve security events and login audit entries.
- `POST /api/audit-logs/clear` — Clear personal audit log events.

---

## 🛡️ Security & Zero-Knowledge Model

1. **Zero Plaintext on Server:** Plaintext message strings and raw image binaries never touch the network wire or server disk unencrypted.
2. **Independent Ephemeral Keys:** A new cryptographically random 128-bit salt and 96-bit nonce are generated for every single message and image encryption operation.
3. **Integrity Protection:** The GCM mode produces an authentication tag appended to the ciphertext. If any byte is altered in transit or in database storage, decryption throws a tamper error before output is displayed.
4. **Argon2id Password Storage:** Passwords protecting accounts are hashed using memory-hard Argon2id parameters.

---

## 🎨 UI/UX Design System

The application uses an **Enterprise Cybersecurity Color Palette**:

```
Background Base     : #0B1220  (Deep Navy)
Surface Background  : #111827  (Navy)
Card Container      : #151F32  (Dark Slate)
Input Background    : #1B2638  (Slate Navy)
Border Color        : #263449  (Slate Blue)
Primary Accent      : #2563EB  (Professional Blue)
Secondary Accent    : #3B82F6  (Steel Blue)
Text Primary        : #F1F5F9  (Off-White)
Text Secondary      : #94A3B8  (Slate)
Text Muted          : #64748B  (Muted Slate)
Success Status      : #10B981  (Emerald)
Warning Status      : #F59E0B  (Amber)
Error Status        : #EF4444  (Red)
```

---

## 📜 Academic / Project Note

This project is developed as an academic implementation showcasing modern Web Cryptography, zero-knowledge architecture, and secure client-server end-to-end communication principles.
#   m e s s a g e - i m a g e - e d  
 