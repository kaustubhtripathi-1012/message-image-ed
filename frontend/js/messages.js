/**
 * SecureVault — messages.js
 * Encrypted message compose, inbox, and client-side decrypt UI.
 */

'use strict';

const MessagesModule = (() => {

  /* ── State ──────────────────────────────────────────────────────────────── */
  let _currentBox  = 'received';   // 'received' | 'sent'
  let _currentMsg  = null;         // Message object being decrypted
  let _messages    = [];

  /* ── Helpers ────────────────────────────────────────────────────────────── */
  function fmt(isoStr) {
    const d = new Date(isoStr + 'Z');
    return d.toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' });
  }

  /* ── Stepper ────────────────────────────────────────────────────────────── */
  const STEPS = ['mstep-validate', 'mstep-derive', 'mstep-encrypt', 'mstep-send'];

  function stepperShow() {
    document.getElementById('msg-stepper').classList.remove('hidden');
    STEPS.forEach(id => {
      const el = document.getElementById(id);
      el.classList.remove('active', 'done');
    });
  }
  function stepperHide() {
    document.getElementById('msg-stepper').classList.add('hidden');
  }
  function stepActive(idx) {
    STEPS.forEach((id, i) => {
      const el = document.getElementById(id);
      el.classList.toggle('active', i === idx);
      if (i < idx) el.classList.add('done');
    });
  }
  function stepAllDone() {
    STEPS.forEach(id => {
      const el = document.getElementById(id);
      el.classList.remove('active');
      el.classList.add('done');
    });
  }

  /* ── Fingerprint display ────────────────────────────────────────────────── */
  let _fpTimer = null;
  async function updateFingerprint(passphrase) {
    const el = document.getElementById('msg-fingerprint');
    if (!el) return;
    if (!passphrase) { el.textContent = ''; return; }
    const fp = await CryptoVault.getFingerprint(passphrase);
    el.textContent = '🔑 Key Fingerprint: ' + fp;
  }

  /* ── Load users into recipient dropdown ─────────────────────────────────── */
  async function refreshRecipients() {
    const select = document.getElementById('msg-recipient');
    if (!select) return;
    try {
      // ONLY load recipients who have an ACCEPTED transfer request!
      const users = await AuthModule.fetchUsers(true);
      const prevVal = select.value;
      select.innerHTML = '<option value="">Select recipient…</option>';
      if (!users.length) {
        select.value = '';
        return;
      }
      users.forEach(u => {
        const opt = document.createElement('option');
        opt.value       = u.username;
        opt.textContent = u.username;
        select.appendChild(opt);
      });
      if (prevVal && users.some(u => u.username.toLowerCase() === prevVal.toLowerCase())) {
        select.value = prevVal;
      } else {
        select.value = '';
      }
    } catch (_) { /* ignore */ }
  }

  /* ── Fetch inbox / sent ─────────────────────────────────────────────────── */
  async function fetchMessages() {
    const endpoint = _currentBox === 'received'
      ? '/api/messages/inbox'
      : '/api/messages/sent';
    try {
      const res = await fetch(endpoint, { headers: AuthModule.authHeader() });
      if (!res.ok) return;
      _messages = await res.json();
      renderList();
    } catch (err) {
      console.error('fetchMessages:', err);
    }
  }

  /* ── Render list ─────────────────────────────────────────────────────────── */
  function renderList() {
    const list = document.getElementById('inbox-list');
    if (!_messages.length) {
      list.innerHTML = '<div class="empty-state">📭 No messages yet</div>';
      return;
    }
    list.innerHTML = '';
    _messages.forEach(msg => {
      const item = document.createElement('div');
      item.className = 'msg-item';
      const peer    = _currentBox === 'received' ? msg.sender : msg.recipient;
      const dirIcon = _currentBox === 'received' ? '📩' : '📤';

      item.innerHTML = `
        <div class="msg-item-info">
          <div class="msg-item-from">
            ${dirIcon} <strong>${escHtml(peer)}</strong>
            <span class="msg-item-badge">AES-256-GCM</span>
          </div>
          <div class="msg-item-time">🕐 ${fmt(msg.created_at)}</div>
        </div>
        <div class="msg-actions">
          <button class="btn btn-ghost btn-xs decrypt-btn" title="Decrypt message" aria-label="Decrypt message from ${escHtml(peer)}">🔓</button>
          <button class="btn btn-ghost btn-xs delete-btn"  title="Delete message"  aria-label="Delete message from ${escHtml(peer)}">🗑</button>
        </div>
      `;

      // Decrypt button
      item.querySelector('.decrypt-btn').addEventListener('click', e => {
        e.stopPropagation();
        openDecryptModal(msg);
      });

      // Delete button — uses raw peer name in confirm() (plain text, not HTML)
      item.querySelector('.delete-btn').addEventListener('click', async e => {
        e.stopPropagation();
        const direction = _currentBox === 'received' ? `from "${peer}"` : `to "${peer}"`;
        if (!confirm(`Permanently delete this message ${direction}?\n\nThis cannot be undone.`)) return;

        const btn = e.currentTarget;
        btn.disabled    = true;
        btn.textContent = '⏳';

        const ok = await deleteMessage(msg.id);
        if (ok) {
          // Animate the row out, then refresh
          item.style.transition = 'opacity 0.25s, transform 0.25s';
          item.style.opacity    = '0';
          item.style.transform  = 'translateX(12px)';
          setTimeout(() => fetchMessages(), 280);
        } else {
          // Restore button so user can retry
          btn.disabled    = false;
          btn.textContent = '🗑';
        }
      });

      // Row click → open decrypt modal, but only if no button was clicked
      item.addEventListener('click', e => {
        if (e.target.closest('button')) return;
        openDecryptModal(msg);
      });

      list.appendChild(item);
    });
  }

  /* ── Delete ─────────────────────────────────────────────────────────────── */
  /**
   * Delete a message via the API.
   * @returns {Promise<boolean>} true on success, false on error
   */
  async function deleteMessage(id) {
    try {
      const res  = await fetch(`/api/messages/${id}`, {
        method:  'DELETE',
        headers: AuthModule.authHeader(),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const reason = data.error || `Server error (${res.status})`;
        AppToast.show(reason, 'error', 'Delete Failed');
        return false;
      }
      AppToast.show('Message deleted', 'info', '🗑 Removed');
      return true;
    } catch (err) {
      AppToast.show('Network error — could not delete message', 'error');
      return false;
    }
  }

  /* ── Open decrypt modal ─────────────────────────────────────────────────── */
  function openDecryptModal(msg) {
    _currentMsg = msg;
    const modal = document.getElementById('msg-modal');
    modal.classList.remove('hidden');
    document.getElementById('msg-modal-meta').innerHTML = `
      <div class="meta-row">
        <span class="meta-key">${_currentBox === 'received' ? 'From' : 'To'}</span>
        <span class="meta-val">${escHtml(_currentBox === 'received' ? msg.sender : msg.recipient)}</span>
      </div>
      <div class="meta-row">
        <span class="meta-key">Date</span>
        <span class="meta-val">${fmt(msg.created_at)}</span>
      </div>
      <div class="meta-row">
        <span class="meta-key">Algorithm</span>
        <span class="meta-val">AES-256-GCM / PBKDF2-SHA-256</span>
      </div>
      <div class="meta-row">
        <span class="meta-key">Version</span>
        <span class="meta-val">v${msg.version}</span>
      </div>
    `;
    // Reset result
    document.getElementById('dec-result').hidden = true;
    document.getElementById('dec-error').hidden  = true;
    document.getElementById('dec-passphrase').value = '';
    document.getElementById('dec-passphrase').focus();
  }

  /* ── Close modal ─────────────────────────────────────────────────────────── */
  function closeModal() {
    const modal = document.getElementById('msg-modal');
    modal.classList.add('hidden');
    _currentMsg = null;
    // Clear sensitive data from DOM
    document.getElementById('plaintext-output').textContent = '';
    document.getElementById('dec-passphrase').value = '';
    document.getElementById('dec-result').hidden = true;
  }

  /* ── Send encrypted message ─────────────────────────────────────────────── */
  async function sendMessage() {
    const recipient  = document.getElementById('msg-recipient').value;
    const passphrase = document.getElementById('msg-passphrase').value;
    const text       = document.getElementById('msg-text').value.trim();
    const sendBtn    = document.getElementById('send-msg-btn');

    if (!recipient) { AppToast.show('Please select a recipient', 'warning'); return; }
    if (!passphrase) { AppToast.show('Please enter a shared passphrase', 'warning'); return; }
    if (!text) { AppToast.show('Message cannot be empty', 'warning'); return; }
    if (text.length > 65536) { AppToast.show('Message too long (max 64KB)', 'error'); return; }

    sendBtn.disabled = true;
    sendBtn.innerHTML = '⏳ Encrypting…';
    stepperShow();

    try {
      // Step 1 — Validate
      stepActive(0);
      await sleep(80);

      // Step 2 — Derive key (PBKDF2 runs here)
      stepActive(1);
      const encrypted = await CryptoVault.encryptMessage(text, passphrase);

      // Step 3 — Encrypt (already done above, just visual)
      stepActive(2);
      await sleep(60);

      // Step 4 — Send ciphertext to server
      stepActive(3);
      const res = await fetch('/api/messages', {
        method:  'POST',
        headers: {
          'Content-Type': 'application/json',
          ...AuthModule.authHeader(),
        },
        body: JSON.stringify({
          recipient,
          ciphertext: encrypted.ciphertext,
          nonce:      encrypted.nonce,
          salt:       encrypted.salt,
          version:    encrypted.version,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Send failed');

      stepAllDone();
      AppToast.show(`Message sent to ${recipient} 🔒`, 'success', 'Encrypted & Delivered');

      // Clear form
      document.getElementById('msg-text').value = '';
      document.getElementById('msg-passphrase').value = '';
      document.getElementById('msg-fingerprint').textContent = '';
      document.getElementById('msg-char-count').textContent = '(0 / 65 536)';

      setTimeout(() => stepperHide(), 1500);
      await fetchMessages();
    } catch (err) {
      AppToast.show(err.message || 'Encryption failed', 'error');
      stepperHide();
    } finally {
      sendBtn.disabled  = false;
      sendBtn.innerHTML = '<span aria-hidden="true">🔒</span> Encrypt &amp; Send';
    }
  }

  /* ── Decrypt message ─────────────────────────────────────────────────────── */
  async function decryptMessage() {
    if (!_currentMsg) return;
    const passphrase = document.getElementById('dec-passphrase').value;
    const btn = document.getElementById('do-decrypt-msg');
    if (!passphrase) { showDecErr('Please enter the shared passphrase'); return; }

    btn.disabled    = true;
    btn.textContent = '⏳ Verifying & Decrypting…';
    document.getElementById('dec-error').hidden  = true;
    document.getElementById('dec-result').hidden = true;

    try {
      const plaintext = await CryptoVault.decryptMessage(
        _currentMsg.ciphertext,
        _currentMsg.nonce,
        _currentMsg.salt,
        passphrase
      );
      document.getElementById('plaintext-output').textContent = plaintext;
      document.getElementById('dec-result').hidden = false;
      AppToast.show('Message decrypted successfully', 'success', '✅ Integrity Verified');
    } catch (err) {
      const isIntegrityFail = err instanceof DOMException;
      const msg = isIntegrityFail
        ? '⛔ Authentication failed — wrong passphrase or message was tampered'
        : (err.message || 'Decryption failed');
      showDecErr(msg);
      AppToast.show('Decryption failed', 'error');
    } finally {
      btn.disabled    = false;
      btn.innerHTML   = '<span aria-hidden="true">🔓</span> Verify &amp; Decrypt';
    }
  }

  function showDecErr(msg) {
    const el = document.getElementById('dec-error');
    el.textContent = msg;
    el.hidden = false;
  }

  /* ── Bind UI ─────────────────────────────────────────────────────────────── */
  function init() {
    document.getElementById('send-msg-btn').addEventListener('click', sendMessage);
    document.getElementById('refresh-inbox').addEventListener('click', fetchMessages);
    document.getElementById('do-decrypt-msg').addEventListener('click', decryptMessage);
    document.getElementById('close-msg-modal').addEventListener('click', closeModal);
    document.getElementById('msg-modal-backdrop').addEventListener('click', closeModal);

    // Mini tabs (scoped to messages inbox)
    document.querySelectorAll('#section-messages .mini-tab').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('#section-messages .mini-tab').forEach(b => {
          b.classList.remove('active');
          b.setAttribute('aria-selected', 'false');
        });
        btn.classList.add('active');
        btn.setAttribute('aria-selected', 'true');
        _currentBox = btn.dataset.box;
        fetchMessages();
      });
    });

    // Char counter
    document.getElementById('msg-text').addEventListener('input', e => {
      document.getElementById('msg-char-count').textContent =
        `(${e.target.value.length.toLocaleString()} / 65 536)`;
    });

    // Passphrase fingerprint
    document.getElementById('msg-passphrase').addEventListener('input', e => {
      clearTimeout(_fpTimer);
      _fpTimer = setTimeout(() => updateFingerprint(e.target.value), 400);
    });

    // Decrypt on Enter in passphrase field
    document.getElementById('dec-passphrase').addEventListener('keydown', e => {
      if (e.key === 'Enter') { e.preventDefault(); decryptMessage(); }
    });
  }

  async function selectRecipient(username) {
    const select = document.getElementById('msg-recipient');
    if (!select) return;
    await refreshRecipients();
    let found = false;
    for (let i = 0; i < select.options.length; i++) {
      if (select.options[i].value && select.options[i].value.toLowerCase() === username.toLowerCase()) {
        select.selectedIndex = i;
        found = true;
        break;
      }
    }
    if (found) {
      const txt = document.getElementById('msg-text') || document.getElementById('msg-plaintext');
      if (txt) setTimeout(() => txt.focus(), 150);
      AppToast.show(`Recipient selected: ${username}`, 'info', '💬 Message Ready');
    } else {
      select.value = '';
      AppToast.show(`Cannot message "${username}" yet — transfer request is not accepted. Send transfer request first!`, 'warning', '⚠️ Transfer Not Accepted');
    }
  }

  function onActivate() {
    refreshRecipients();
    fetchMessages();
  }

  return { init, onActivate, refreshRecipients, selectRecipient };

})();

/* ── Tiny sleep util ─────────────────────────────────────────────────────── */
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/* ── HTML escape ─────────────────────────────────────────────────────────── */
function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
