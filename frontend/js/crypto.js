/**
 * SecureVault — crypto.js
 * All cryptographic operations using the browser-native Web Crypto API.
 * No external libraries required.
 *
 * Algorithm:  AES-256-GCM  (AEAD — authenticated encryption)
 * Key derive: PBKDF2-SHA-256, 100 000 iterations
 * Nonce/IV:   96-bit  (12 bytes) — fresh per operation via OS CSPRNG
 * Salt:       128-bit (16 bytes) — fresh per operation via OS CSPRNG
 *
 * AES-GCM automatically appends a 128-bit authentication tag to the
 * ciphertext output.  Any modification to the ciphertext or metadata causes
 * crypto.subtle.decrypt() to throw, enabling tamper detection.
 */

'use strict';

const CryptoVault = (() => {

  /* ── Helpers ──────────────────────────────────────────────────────────── */

  /**
   * Convert ArrayBuffer → base64 string.
   * Handles large buffers in chunks to avoid call-stack overflow.
   */
  function bufToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    const chunkSize = 8192;
    for (let i = 0; i < bytes.length; i += chunkSize) {
      binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
    }
    return btoa(binary);
  }

  /**
   * Convert base64 string → ArrayBuffer.
   */
  function base64ToBuf(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  /**
   * Generate a human-readable hex fingerprint for a passphrase.
   * Used only for display — never for key derivation.
   */
  async function getFingerprint(passphrase) {
    if (!passphrase) return '';
    const enc = new TextEncoder();
    const hash = await crypto.subtle.digest(
      'SHA-256',
      enc.encode('sv-fingerprint:' + passphrase)
    );
    return Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
      .match(/.{1,4}/g)
      .join(' ')
      .toUpperCase();
  }

  /* ── Key Derivation ───────────────────────────────────────────────────── */

  /**
   * Derive an AES-256-GCM CryptoKey from a passphrase + salt.
   *
   * @param {string}      passphrase  - User passphrase (UTF-8)
   * @param {ArrayBuffer|Uint8Array} salt - 16-byte random salt
   * @returns {Promise<CryptoKey>}
   */
  async function deriveKey(passphrase, salt) {
    const enc = new TextEncoder();
    const saltBuf = salt instanceof ArrayBuffer ? salt : salt.buffer;

    // Import passphrase as PBKDF2 key material
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      enc.encode(passphrase),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    // Derive AES-256-GCM key
    return crypto.subtle.deriveKey(
      {
        name:       'PBKDF2',
        salt:       saltBuf,
        iterations: 100_000,
        hash:       'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,                        // not extractable — key stays in browser
      ['encrypt', 'decrypt']
    );
  }

  /* ── Message Encryption / Decryption ─────────────────────────────────── */

  /**
   * Encrypt a UTF-8 plaintext message with AES-256-GCM.
   *
   * @param {string} plaintext
   * @param {string} passphrase
   * @returns {Promise<{ciphertext:string, nonce:string, salt:string, version:number}>}
   *          All buffers are base64-encoded for transport.
   */
  async function encryptMessage(plaintext, passphrase) {
    // Fresh random material for every encryption — nonce MUST never be reused
    const salt  = crypto.getRandomValues(new Uint8Array(16));  // 128-bit
    const nonce = crypto.getRandomValues(new Uint8Array(12));  // 96-bit

    const key = await deriveKey(passphrase, salt);
    const enc = new TextEncoder();

    // AES-GCM output = ciphertext || 128-bit authentication tag (appended automatically)
    const ciphertextBuf = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, tagLength: 128 },
      key,
      enc.encode(plaintext)
    );

    return {
      ciphertext: bufToBase64(ciphertextBuf),
      nonce:      bufToBase64(nonce.buffer),
      salt:       bufToBase64(salt.buffer),
      version:    1,
    };
  }

  /**
   * Decrypt and verify an AES-256-GCM ciphertext.
   * Throws if integrity verification fails (tampered data or wrong key).
   *
   * @param {string} ciphertext - base64 AES-GCM output (ciphertext + auth tag)
   * @param {string} nonce      - base64 96-bit nonce
   * @param {string} salt       - base64 128-bit PBKDF2 salt
   * @param {string} passphrase
   * @returns {Promise<string>} Plaintext message
   */
  async function decryptMessage(ciphertext, nonce, salt, passphrase) {
    const key = await deriveKey(passphrase, new Uint8Array(base64ToBuf(salt)));

    // Will throw DOMException if auth tag is invalid (tampered or wrong key)
    const plaintextBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBuf(nonce), tagLength: 128 },
      key,
      base64ToBuf(ciphertext)
    );

    return new TextDecoder().decode(plaintextBuf);
  }

  /* ── Image Encryption / Decryption ───────────────────────────────────── */

  /**
   * Encrypt an image ArrayBuffer with AES-256-GCM.
   *
   * @param {ArrayBuffer} arrayBuffer - Raw image bytes
   * @param {string}      passphrase
   * @param {Function}    [onProgress] - (pct:number, label:string) => void
   * @returns {Promise<{encryptedBuffer:ArrayBuffer, nonce:string, salt:string, version:number}>}
   */
  async function encryptImage(arrayBuffer, passphrase, onProgress) {
    const salt  = crypto.getRandomValues(new Uint8Array(16));
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    onProgress?.(15, 'Deriving AES-256 key (PBKDF2)…');
    const key = await deriveKey(passphrase, salt);

    onProgress?.(45, 'Encrypting with AES-256-GCM…');
    const encryptedBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, tagLength: 128 },
      key,
      arrayBuffer
    );

    onProgress?.(90, 'Encryption complete');

    return {
      encryptedBuffer,
      nonce:   bufToBase64(nonce.buffer),
      salt:    bufToBase64(salt.buffer),
      version: 1,
    };
  }

  /**
   * Decrypt an encrypted image ArrayBuffer with AES-256-GCM.
   * Throws if integrity verification fails.
   *
   * @param {ArrayBuffer} encryptedBuffer
   * @param {string}      nonce      - base64
   * @param {string}      salt       - base64
   * @param {string}      passphrase
   * @returns {Promise<ArrayBuffer>} Original image bytes
   */
  async function decryptImage(encryptedBuffer, nonce, salt, passphrase) {
    const key = await deriveKey(passphrase, new Uint8Array(base64ToBuf(salt)));

    return crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBuf(nonce), tagLength: 128 },
      key,
      encryptedBuffer
    );
  }

  /* ── Public API ───────────────────────────────────────────────────────── */
  return {
    encryptMessage,
    decryptMessage,
    encryptImage,
    decryptImage,
    getFingerprint,
    bufToBase64,
    base64ToBuf,
  };

})();
