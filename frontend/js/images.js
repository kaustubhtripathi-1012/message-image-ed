/**
 * SecureVault — images.js
 * Client-side image encryption, encrypted upload, gallery, and decrypt/display.
 */

'use strict';

const ImagesModule = (() => {

  /* ── State ──────────────────────────────────────────────────────────────── */
  let _selectedFile     = null;      // File object from picker/drop
  let _currentImgMeta   = null;      // Metadata of image being decrypted
  let _decryptedBlobUrl = null;      // Blob URL for decrypted image (to revoke)
  let _currentImgBox    = 'received';// 'received' | 'sent'

  /* ── Helpers ────────────────────────────────────────────────────────────── */
  const ALLOWED_TYPES  = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/jpg']);
  const MAX_IMAGE_SIZE = 25 * 1024 * 1024;   // 25 MB

  function fmtSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 ** 2) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1024 ** 2).toFixed(2) + ' MB';
  }
  function fmt(isoStr) {
    const d = new Date(isoStr + 'Z');
    return d.toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' });
  }

  /* ── Progress helpers ────────────────────────────────────────────────────── */
  const PSTEPS = ['pstep-validate', 'pstep-key', 'pstep-encrypt', 'pstep-upload'];

  function progShow() {
    document.getElementById('img-progress').classList.remove('hidden');
    PSTEPS.forEach(id => {
      const el = document.getElementById(id);
      el.classList.remove('active', 'done');
    });
    setProgress(0, 'Preparing…');
  }
  function progHide() {
    document.getElementById('img-progress').classList.add('hidden');
  }
  function progStep(idx) {
    PSTEPS.forEach((id, i) => {
      const el = document.getElementById(id);
      el.classList.toggle('active', i === idx);
      if (i < idx) el.classList.add('done');
    });
  }
  function progAllDone() {
    PSTEPS.forEach(id => {
      document.getElementById(id).classList.replace?.('active', 'done') ||
      (() => {
        const el = document.getElementById(id);
        el.classList.remove('active');
        el.classList.add('done');
      })();
    });
    setProgress(100, 'Done ✓');
  }
  function setProgress(pct, label) {
    const bar = document.getElementById('img-prog-bar');
    if (bar) bar.style.width = pct + '%';
    const lbl = document.getElementById('img-prog-label');
    if (lbl) lbl.textContent = label;
    const wrap = document.getElementById('img-prog-bar-wrap');
    if (wrap) wrap.setAttribute('aria-valuenow', pct);
  }

  /* ── File selection ──────────────────────────────────────────────────────── */
  function selectFile(file) {
    if (!file) return;
    if (!ALLOWED_TYPES.has(file.type)) {
      AppToast.show('Unsupported format. Use JPEG, PNG or WebP.', 'error');
      return;
    }
    if (file.size > MAX_IMAGE_SIZE) {
      AppToast.show(`File too large. Max is ${fmtSize(MAX_IMAGE_SIZE)}.`, 'error');
      return;
    }
    _selectedFile = file;
    showPreview(file);
  }

  function showPreview(file) {
    const dropZone   = document.getElementById('drop-zone');
    const previewArea = document.getElementById('img-preview-area');
    const preview    = document.getElementById('img-preview');
    const info       = document.getElementById('img-file-info');

    const url = URL.createObjectURL(file);
    preview.src = url;
    preview.onload = () => URL.revokeObjectURL(url);  // Clean up blob URL

    info.innerHTML = `
      <div class="file-info-name">${escHtml(file.name)}</div>
      <div class="file-info-size">${fmtSize(file.size)} · ${file.type}</div>
    `;
    dropZone.classList.add('hidden');
    previewArea.classList.remove('hidden');
  }

  function clearFile() {
    _selectedFile = null;
    document.getElementById('img-preview').src = '';
    document.getElementById('img-file-info').innerHTML = '';
    document.getElementById('img-preview-area').classList.add('hidden');
    document.getElementById('drop-zone').classList.remove('hidden');
    document.getElementById('img-file-input').value = '';
  }

  /* ── Encrypt & Upload ────────────────────────────────────────────────────── */
  async function encryptAndUpload() {
    const passphrase = document.getElementById('img-passphrase').value;
    const btn        = document.getElementById('upload-img-btn');

    if (!_selectedFile) { AppToast.show('Please select an image first', 'warning'); return; }
    if (!passphrase)     { AppToast.show('Please enter an encryption passphrase', 'warning'); return; }

    btn.disabled    = true;
    btn.textContent = '⏳ Encrypting…';
    progShow();

    try {
      // Step 1 — Validate
      progStep(0);
      setProgress(5, 'Validating file…');
      await sleep(60);

      // Step 2 — Read file + derive key
      progStep(1);
      setProgress(15, 'Reading file & deriving AES-256 key (PBKDF2)…');
      const arrayBuffer = await readFileAsArrayBuffer(_selectedFile);

      // Step 3 — Encrypt (progress callback)
      progStep(2);
      const result = await CryptoVault.encryptImage(arrayBuffer, passphrase, (pct, label) => {
        setProgress(15 + pct * 0.55, label);
      });
      setProgress(70, 'Preparing upload…');

      // Step 4 — Upload encrypted blob
      progStep(3);
      setProgress(75, 'Uploading ciphertext…');

      const formData = new FormData();
      formData.append('file', new Blob([result.encryptedBuffer], { type: 'application/octet-stream' }), 'encrypted.bin');
      formData.append('nonce',         result.nonce);
      formData.append('salt',          result.salt);
      const recipientSelect = document.getElementById('img-recipient');
      const recipient = recipientSelect ? recipientSelect.value.trim() : '';
      if (recipient) {
        formData.append('recipient', recipient);
      }

      formData.append('content_type',  _selectedFile.type);
      formData.append('original_name', _selectedFile.name);
      formData.append('version',       String(result.version));

      const res = await fetch('/api/images', {
        method:  'POST',
        headers: AuthModule.authHeader(),
        body:    formData,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Upload failed');

      progAllDone();
      AppToast.show(`Image encrypted & uploaded 🔒`, 'success', 'Upload Complete');

      // Clean up
      clearFile();
      document.getElementById('img-passphrase').value = '';
      setTimeout(() => progHide(), 1800);

      // If sent to another user, switch to Sent tab so user can see their uploaded image
      if (recipient && _currentImgBox !== 'sent') {
        _currentImgBox = 'sent';
        const tabRec  = document.getElementById('img-tab-received');
        const tabSent = document.getElementById('img-tab-sent');
        if (tabRec && tabSent) {
          tabSent.classList.add('active');
          tabRec.classList.remove('active');
          tabSent.setAttribute('aria-selected', 'true');
          tabRec.setAttribute('aria-selected', 'false');
        }
      }

      await fetchGallery();
    } catch (err) {
      progHide();
      AppToast.show(err.message || 'Encryption failed', 'error');
    } finally {
      btn.disabled    = false;
      btn.innerHTML   = '<span aria-hidden="true">🔒</span> Encrypt &amp; Upload';
    }
  }

  /* ── Recipients dropdown for image upload ────────────────────────────────── */
  async function refreshRecipients() {
    const select = document.getElementById('img-recipient');
    if (!select) return;
    try {
      // ONLY load recipients who have an ACCEPTED transfer request!
      const users = await AuthModule.fetchUsers(true);
      const prevVal = select.value;
      select.innerHTML = '<option value="">Select recipient (or self)…</option>';
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

  /* ── Gallery / Images Inbox ───────────────────────────────────────────────── */
  async function fetchGallery() {
    const gallery = document.getElementById('img-gallery');
    if (!gallery) return;

    // Loading indicator
    gallery.innerHTML = '<div class="loading-placeholder" style="grid-column: 1 / -1; text-align: center; padding: 2rem; color: var(--text-3);">⏳ Loading encrypted images…</div>';

    try {
      const res = await fetch(`/api/images?box=${_currentImgBox}`, { headers: AuthModule.authHeader() });
      if (!res.ok) {
        gallery.innerHTML = `
          <div class="empty-state" style="grid-column: 1 / -1; text-align: center; padding: 2rem;">
            ⚠️ Failed to load ${_currentImgBox} images
            <div style="margin-top: 0.6rem;">
              <button class="btn btn-ghost btn-xs" id="retry-gallery-btn">↻ Retry</button>
            </div>
          </div>
        `;
        document.getElementById('retry-gallery-btn')?.addEventListener('click', fetchGallery);
        return;
      }
      const images = await res.json();

      if (!images.length) {
        const icon = _currentImgBox === 'received' ? '📭' : '📤';
        const label = _currentImgBox === 'received' ? 'received' : 'sent';
        gallery.innerHTML = `
          <div class="empty-state" style="grid-column: 1 / -1; text-align: center; padding: 2.5rem 1rem;">
            <div style="font-size: 2rem; margin-bottom: 0.4rem;">${icon}</div>
            <div>No ${label} encrypted images yet</div>
            <div style="font-size: 0.75rem; color: var(--text-3); margin-top: 0.3rem;">
              ${_currentImgBox === 'received' ? 'Encrypted images sent to you will appear here' : 'Images you encrypt and send will appear here'}
            </div>
          </div>
        `;
        return;
      }
      gallery.innerHTML = '';
      images.forEach(img => {
        const card = document.createElement('div');
        card.className = 'img-card';
        const typeEmoji = { 'image/jpeg': '📸', 'image/png': '🖼️', 'image/webp': '🌐', 'image/jpg': '📸' };
        const icon = typeEmoji[img.content_type] || '🔒';
        const isSelf = img.sender === img.recipient;
        let peerLabel;
        if (_currentImgBox === 'received') {
          peerLabel = `📩 From: <strong>${escHtml(isSelf ? `${img.sender} (self)` : (img.sender || 'unknown'))}</strong>`;
        } else {
          peerLabel = `📤 To: <strong>${escHtml(isSelf ? 'self' : (img.recipient || 'self'))}</strong>`;
        }

        card.innerHTML = `
          <div class="img-card-thumb">${icon}</div>
          <div class="img-card-info">
            <div class="img-card-name" title="${escHtml(img.original_name)}">${escHtml(img.original_name)}</div>
            <div class="img-card-size">${fmtSize(img.encrypted_size)}</div>
            <div class="img-card-type">🔒 ${escHtml(img.content_type)}</div>
            <div class="img-card-peer">${peerLabel}</div>
            <div class="img-card-time" style="font-size: 0.65rem; color: var(--text-3); margin-top: 0.15rem;">🕐 ${fmt(img.created_at)}</div>
          </div>
          <div class="img-card-actions">
            <button class="btn btn-ghost btn-xs dec-img-btn" title="Decrypt image" aria-label="Decrypt image ${escHtml(img.original_name)}">🔓 Decrypt</button>
            <button class="btn btn-ghost btn-xs del-img-btn" title="Delete image"  aria-label="Delete ${escHtml(img.original_name)}">🗑</button>
          </div>
        `;
        card.querySelector('.dec-img-btn').addEventListener('click', e => {
          e.stopPropagation();
          openImgDecryptModal(img);
        });
        const delBtn = card.querySelector('.del-img-btn');
        delBtn.addEventListener('click', async e => {
          e.stopPropagation();
          if (!confirm(`Permanently delete "${img.original_name}"?\n\nThe encrypted blob will be removed from the server.`)) return;
          delBtn.disabled   = true;
          delBtn.textContent = '⏳';
          const ok = await deleteImage(img.id);
          if (ok) {
            card.style.transition = 'opacity 0.25s, transform 0.25s';
            card.style.opacity   = '0';
            card.style.transform = 'scale(0.9)';
            setTimeout(() => fetchGallery(), 260);
          } else {
            delBtn.disabled   = false;
            delBtn.textContent = '🗑';
          }
        });
        // Card click opens decrypt modal only when clicking outside action buttons
        card.addEventListener('click', e => {
          if (e.target.closest('button')) return;
          openImgDecryptModal(img);
        });
        gallery.appendChild(card);
      });
    } catch (err) {
      console.error('fetchGallery:', err);
      gallery.innerHTML = '<div class="empty-state" style="grid-column: 1 / -1; text-align: center; padding: 2rem;">⚠️ Network error loading encrypted images</div>';
    }
  }

  /**
   * Delete an encrypted image via the API.
   * Also removes the blob file on the server.
   * @returns {Promise<boolean>} true on success, false on error
   */
  async function deleteImage(id) {
    try {
      const res  = await fetch(`/api/images/${id}`, {
        method:  'DELETE',
        headers: AuthModule.authHeader(),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const reason = data.error || `Server error (${res.status})`;
        AppToast.show(reason, 'error', 'Delete Failed');
        return false;
      }
      AppToast.show('Encrypted image deleted from server', 'info', '🗑 Removed');
      return true;
    } catch (err) {
      AppToast.show('Network error — could not delete image', 'error');
      return false;
    }
  }

  /* ── Decrypt modal ────────────────────────────────────────────────────────── */
  function openImgDecryptModal(img) {
    _currentImgMeta = img;
    const modal = document.getElementById('img-modal');
    modal.classList.remove('hidden');

    const peerRow = img.sender
      ? `<div class="meta-row"><span class="meta-key">From</span><span class="meta-val">${escHtml(img.sender)}</span></div>`
      : '';
    document.getElementById('img-modal-meta').innerHTML = `
      <div class="meta-row"><span class="meta-key">File</span>     <span class="meta-val">${escHtml(img.original_name)}</span></div>
      ${peerRow}
      <div class="meta-row"><span class="meta-key">Type</span>     <span class="meta-val">${escHtml(img.content_type)}</span></div>
      <div class="meta-row"><span class="meta-key">Enc. Size</span><span class="meta-val">${fmtSize(img.encrypted_size)}</span></div>
      <div class="meta-row"><span class="meta-key">Algorithm</span><span class="meta-val">AES-256-GCM</span></div>
      <div class="meta-row"><span class="meta-key">Uploaded</span> <span class="meta-val">${fmt(img.created_at)}</span></div>
    `;
    document.getElementById('img-dec-result').classList.add('hidden');
    document.getElementById('img-integrity-badge').classList.add('hidden');
    document.getElementById('img-dec-error').hidden = true;
    document.getElementById('img-dec-passphrase').value = '';
    document.getElementById('img-dec-passphrase').focus();

    // Revoke previous blob URL
    if (_decryptedBlobUrl) { URL.revokeObjectURL(_decryptedBlobUrl); _decryptedBlobUrl = null; }
  }

  function closeImgModal() {
    const modal = document.getElementById('img-modal');
    modal.classList.add('hidden');
    _currentImgMeta = null;
    if (_decryptedBlobUrl) { URL.revokeObjectURL(_decryptedBlobUrl); _decryptedBlobUrl = null; }
    document.getElementById('decrypted-img').src = '';
    document.getElementById('img-dec-passphrase').value = '';
    document.getElementById('img-dec-result').classList.add('hidden');
    document.getElementById('img-integrity-badge').classList.add('hidden');
  }

  async function decryptImage() {
    if (!_currentImgMeta) return;
    const passphrase = document.getElementById('img-dec-passphrase').value;
    const btn        = document.getElementById('do-decrypt-img');
    if (!passphrase) { showImgErr('Please enter the decryption passphrase'); return; }

    btn.disabled    = true;
    btn.textContent = '⏳ Downloading & Decrypting…';
    document.getElementById('img-dec-error').hidden = true;
    document.getElementById('img-dec-result').classList.add('hidden');
    document.getElementById('img-integrity-badge').classList.add('hidden');

    try {
      // 1. Download encrypted binary
      const res = await fetch(`/api/images/${_currentImgMeta.id}/data`, {
        headers: AuthModule.authHeader(),
      });
      if (!res.ok) throw new Error('Download failed');
      const encryptedBuffer = await res.arrayBuffer();

      // 2. Decrypt + verify auth tag (throws if tampered/wrong key)
      const decryptedBuffer = await CryptoVault.decryptImage(
        encryptedBuffer,
        _currentImgMeta.nonce,
        _currentImgMeta.salt,
        passphrase
      );

      // 3. Display
      const blob = new Blob([decryptedBuffer], { type: _currentImgMeta.content_type });
      if (_decryptedBlobUrl) URL.revokeObjectURL(_decryptedBlobUrl);
      _decryptedBlobUrl = URL.createObjectURL(blob);

      const imgEl = document.getElementById('decrypted-img');
      imgEl.src = _decryptedBlobUrl;
      imgEl.alt = `Decrypted: ${_currentImgMeta.original_name}`;

      // Set download link
      const dlLink = document.getElementById('download-decrypted-img');
      dlLink.href     = _decryptedBlobUrl;
      dlLink.download = _currentImgMeta.original_name || 'decrypted_image';

      document.getElementById('img-integrity-badge').classList.remove('hidden');
      document.getElementById('img-dec-result').classList.remove('hidden');
      AppToast.show('Image decrypted & verified ✅', 'success', 'Integrity Confirmed');
    } catch (err) {
      const isIntegrityFail = err instanceof DOMException;
      const msg = isIntegrityFail
        ? '⛔ Authentication failed — wrong passphrase or image data was tampered'
        : (err.message || 'Decryption failed');
      showImgErr(msg);
      AppToast.show('Decryption failed', 'error');
    } finally {
      btn.disabled    = false;
      btn.innerHTML   = '<span aria-hidden="true">🔓</span> Verify Integrity &amp; Decrypt';
    }
  }

  function showImgErr(msg) {
    const el = document.getElementById('img-dec-error');
    el.textContent = msg;
    el.hidden = false;
  }

  /* ── Read file as ArrayBuffer ────────────────────────────────────────────── */
  function readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload  = e => resolve(e.target.result);
      reader.onerror = () => reject(new Error('Failed to read file'));
      reader.readAsArrayBuffer(file);
    });
  }

  /* ── Bind UI ─────────────────────────────────────────────────────────────── */
  function init() {
    const dropZone   = document.getElementById('drop-zone');
    const fileInput  = document.getElementById('img-file-input');

    // Click to open file picker
    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') fileInput.click(); });

    fileInput.addEventListener('change', e => selectFile(e.target.files[0]));

    // Drag and drop
    dropZone.addEventListener('dragover', e => {
      e.preventDefault();
      dropZone.classList.add('drag-over');
    });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
    dropZone.addEventListener('drop', e => {
      e.preventDefault();
      dropZone.classList.remove('drag-over');
      selectFile(e.dataTransfer.files[0]);
    });

    document.getElementById('remove-img').addEventListener('click', e => {
      e.stopPropagation();
      clearFile();
    });

    document.getElementById('upload-img-btn').addEventListener('click', encryptAndUpload);
    document.getElementById('refresh-gallery').addEventListener('click', fetchGallery);

    document.getElementById('do-decrypt-img').addEventListener('click', decryptImage);
    document.getElementById('close-img-modal').addEventListener('click', closeImgModal);
    document.getElementById('img-modal-backdrop').addEventListener('click', closeImgModal);
    document.getElementById('img-dec-passphrase').addEventListener('keydown', e => {
      if (e.key === 'Enter') { e.preventDefault(); decryptImage(); }
    });

    // Received / Sent tabs for images
    const tabRec = document.getElementById('img-tab-received');
    const tabSent = document.getElementById('img-tab-sent');
    if (tabRec && tabSent) {
      tabRec.addEventListener('click', () => {
        _currentImgBox = 'received';
        tabRec.classList.add('active');
        tabSent.classList.remove('active');
        tabRec.setAttribute('aria-selected', 'true');
        tabSent.setAttribute('aria-selected', 'false');
        fetchGallery();
      });
      tabSent.addEventListener('click', () => {
        _currentImgBox = 'sent';
        tabSent.classList.add('active');
        tabRec.classList.remove('active');
        tabSent.setAttribute('aria-selected', 'true');
        tabRec.setAttribute('aria-selected', 'false');
        fetchGallery();
      });
    }
  }

  async function selectRecipient(username) {
    const select = document.getElementById('img-recipient');
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
      AppToast.show(`Recipient selected for image: ${username}`, 'info', '🖼️ Image Ready');
    } else {
      select.value = '';
      AppToast.show(`Cannot send image to "${username}" yet — transfer request is not accepted.`, 'warning', '⚠️ Transfer Not Accepted');
    }
  }

  function onActivate() {
    refreshRecipients();
    fetchGallery();
  }

  return { init, onActivate, refreshRecipients, selectRecipient, fetchGallery };

})();
