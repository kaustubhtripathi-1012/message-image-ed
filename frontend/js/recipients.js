/**
 * SecureVault — recipients.js
 * Controls the Recipient Search & Add box in the navigation bar.
 * Features:
 * - Click-to-toggle opening and closing of the panel ("when we click then they open otherwise close").
 * - Live recipient search across registered users.
 * - Transfer Request handshake: send request, accept/decline incoming requests.
 * - Enforces accepted transfer rule: "when the recipient accepts the request then show the name, otherwise blank".
 * - Quick jump to compose messages or send encrypted images with recipient pre-selected.
 * - Quick-register new recipients modal with default password123.
 */

'use strict';

const RecipientSearchModule = (() => {

  let _cachedUsers = [];
  let _transferRequests = [];
  let _isOpen = false;

  /* ── DOM References ─────────────────────────────────────────────────────── */
  const dom = {
    container: () => document.getElementById('nav-recipient-container'),
    toggleBtn: () => document.getElementById('btn-toggle-recipient-box'),
    navBadge: () => document.getElementById('nav-rec-badge'),
    dropdown: () => document.getElementById('nav-recipient-dropdown'),
    panelInput: () => document.getElementById('rec-panel-search-input'),
    panelAddBtn: () => document.getElementById('btn-panel-add-rec'),
    backdrop: () => document.getElementById('rec-dropdown-backdrop'),
    closeBtn: () => document.getElementById('btn-close-rec-dropdown'),
    list: () => document.getElementById('rec-dropdown-list'),
    badge: () => document.getElementById('rec-count-badge'),
    transferSection: () => document.getElementById('transfer-requests-section'),
    transferList: () => document.getElementById('transfer-requests-list'),
    transferBadge: () => document.getElementById('incoming-requests-badge'),
    openModalBtn: () => document.getElementById('btn-open-add-recipient-modal'),
    quickAddBtn: () => document.getElementById('btn-rec-quick-register'),
    modal: () => document.getElementById('add-recipient-modal'),
    modalBackdrop: () => document.getElementById('add-rec-backdrop'),
    modalClose: () => document.getElementById('close-add-rec-modal'),
    form: () => document.getElementById('add-recipient-form'),
    uInput: () => document.getElementById('add-rec-username'),
    pInput: () => document.getElementById('add-rec-password'),
    errorEl: () => document.getElementById('add-rec-error'),
    submitBtn: () => document.getElementById('btn-submit-add-recipient'),
  };

  /* ── Load & Refresh Users and Transfers ─────────────────────────────────── */
  async function refreshUsers() {
    try {
      const users = await AuthModule.fetchUsers(false);
      _cachedUsers = Array.isArray(users) ? users : [];
      if (dom.badge()) {
        dom.badge().textContent = _cachedUsers.length;
      }
      if (_isOpen) {
        renderDropdown(dom.panelInput() ? dom.panelInput().value : '');
      }
    } catch (_) {
      _cachedUsers = [];
    }
  }

  async function refreshTransferRequests() {
    try {
      const res = await fetch('/api/transfer-requests', { headers: AuthModule.authHeader() });
      if (!res.ok) return;
      _transferRequests = await res.json();
      renderTransferRequests();
      if (_isOpen) {
        renderDropdown(dom.panelInput() ? dom.panelInput().value : '');
      }
    } catch (_) {
      _transferRequests = [];
    }
  }

  /* ── Render Pending Transfer Requests ───────────────────────────────────── */
  function renderTransferRequests() {
    const sec = dom.transferSection();
    const list = dom.transferList();
    const badge = dom.transferBadge();
    const navBadge = dom.navBadge();
    if (!sec || !list) return;

    const incoming = _transferRequests.filter(r => r.direction === 'incoming' && r.status === 'pending');
    if (badge) badge.textContent = incoming.length;

    // Sync navbar badge
    if (navBadge) {
      navBadge.textContent = incoming.length;
      navBadge.classList.toggle('hidden', incoming.length === 0);
    }

    // Sync with mobile bottom nav badge and header badge
    const mobBadge = document.getElementById('mob-rec-badge');
    if (mobBadge) {
      mobBadge.textContent = incoming.length;
      mobBadge.classList.toggle('hidden', incoming.length === 0);
    }
    const mobHeaderBadge = document.getElementById('mobile-header-rec-badge');
    if (mobHeaderBadge) {
      mobHeaderBadge.textContent = incoming.length;
      mobHeaderBadge.style.display = incoming.length ? '' : 'none';
    }

    if (!incoming.length) {
      sec.classList.add('hidden');
      list.innerHTML = '';
      return;
    }

    sec.classList.remove('hidden');
    list.innerHTML = '';

    incoming.forEach(req => {
      const item = document.createElement('div');
      item.className = 'transfer-req-item';
      item.innerHTML = `
        <div>
          <span>📩 From <strong>${escHtml(req.peer_username)}</strong></span>
        </div>
        <div class="transfer-req-actions">
          <button class="btn-transfer-accept" data-id="${req.id}">✓ Accept</button>
          <button class="btn-transfer-decline" data-id="${req.id}">✕ Decline</button>
        </div>
      `;

      item.querySelector('.btn-transfer-accept').addEventListener('click', async e => {
        e.stopPropagation();
        await handleAcceptTransfer(req.id, req.peer_username);
      });

      item.querySelector('.btn-transfer-decline').addEventListener('click', async e => {
        e.stopPropagation();
        await handleDeclineTransfer(req.id, req.peer_username);
      });

      list.appendChild(item);
    });
  }

  async function handleAcceptTransfer(id, peer) {
    try {
      const res = await fetch(`/api/transfer-requests/${id}/accept`, {
        method: 'POST',
        headers: AuthModule.authHeader(),
      });
      if (res.ok) {
        AppToast.show(`Transfer accepted from ${peer}! 🔒`, 'success', 'Transfer Active');
        await refreshTransferRequests();
        await refreshUsers();
        // Immediately refresh recipient dropdowns across Messages & Images so peer's name appears!
        if (typeof MessagesModule !== 'undefined' && MessagesModule.refreshRecipients) {
          await MessagesModule.refreshRecipients();
        }
        if (typeof ImagesModule !== 'undefined' && ImagesModule.refreshRecipients) {
          await ImagesModule.refreshRecipients();
        }
      }
    } catch (_) {
      AppToast.show('Error accepting transfer request', 'error');
    }
  }

  async function handleDeclineTransfer(id, peer) {
    try {
      const res = await fetch(`/api/transfer-requests/${id}/decline`, {
        method: 'POST',
        headers: AuthModule.authHeader(),
      });
      if (res.ok) {
        AppToast.show(`Transfer declined from ${peer}`, 'info');
        await refreshTransferRequests();
      }
    } catch (_) {
      AppToast.show('Error declining transfer request', 'error');
    }
  }

  async function sendTransferRequest(username) {
    try {
      const res = await fetch('/api/transfer-requests', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...AuthModule.authHeader(),
        },
        body: JSON.stringify({ recipient: username }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        AppToast.show(`Transfer request sent to ${username} 🤝`, 'success', 'Request Sent');
        await refreshTransferRequests();
      } else {
        AppToast.show(data.error || 'Failed to send transfer request', 'error');
      }
    } catch (_) {
      AppToast.show('Network error sending transfer request', 'error');
    }
  }

  /* ── Render Dropdown Items ───────────────────────────────────────────────── */
  function renderDropdown(query = '') {
    const listEl = dom.list();
    if (!listEl) return;
    listEl.innerHTML = '';

    const q = query.trim().toLowerCase();
    const matched = _cachedUsers.filter(u => {
      const name = (u.username || '').toLowerCase();
      return !q || name.includes(q);
    });

    if (matched.length === 0) {
      if (q) {
        const emptyDiv = document.createElement('div');
        emptyDiv.className = 'rec-dropdown-empty';
        emptyDiv.innerHTML = `
          <div style="font-size:0.78rem; color: var(--text-3); margin-bottom:0.4rem;">No recipient found for "<strong>${escHtml(q)}</strong>"</div>
          <button type="button" class="btn btn-xs btn-primary" id="btn-empty-add" style="font-size:0.75rem; width:100%; border-radius:4px;">
            ➕ Register "${escHtml(q)}" as Recipient
          </button>
        `;
        listEl.appendChild(emptyDiv);

        const emptyAddBtn = emptyDiv.querySelector('#btn-empty-add');
        if (emptyAddBtn) {
          emptyAddBtn.addEventListener('click', e => {
            e.stopPropagation();
            closeDropdown();
            openAddModal(q);
          });
        }
      } else {
        const emptyDiv = document.createElement('div');
        emptyDiv.className = 'rec-dropdown-empty';
        emptyDiv.style.cssText = 'padding: 0.8rem; font-size: 0.8rem; color: var(--text-3); text-align: center;';
        emptyDiv.textContent = 'No other recipients registered yet';
        listEl.appendChild(emptyDiv);
      }
      return;
    }

    matched.forEach(u => {
      const item = document.createElement('div');
      item.className = 'rec-dropdown-item';
      item.setAttribute('role', 'option');

      const initial = (u.username || '?').charAt(0).toUpperCase();
      let displayName = escHtml(u.username);
      if (q) {
        const regex = new RegExp(`(${q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
        displayName = escHtml(u.username).replace(regex, '<span class="rec-match">$1</span>');
      }

      // Check transfer status with this user
      const tr = _transferRequests.find(r =>
        (r.peer_username || '').toLowerCase() === (u.username || '').toLowerCase()
      );
      const isAccepted = tr && tr.status === 'accepted';
      const isPending = tr && tr.status === 'pending';

      let transferActionHtml = '';
      if (isAccepted) {
        transferActionHtml = `
          <span class="transfer-status-badge accepted" title="Transfer active and verified">✅ Active</span>
          <button class="btn btn-xs btn-ghost btn-rec-msg" title="Send message to ${escHtml(u.username)}">💬</button>
          <button class="btn btn-xs btn-ghost btn-rec-img" title="Send image to ${escHtml(u.username)}">🖼️</button>
        `;
      } else if (isPending) {
        if (tr.direction === 'outgoing') {
          transferActionHtml = `<span class="transfer-status-badge pending" title="Waiting for acceptance">⏳ Requested</span>`;
        } else {
          transferActionHtml = `<button class="btn-transfer-accept btn-inline-accept" data-id="${tr.id}" title="Accept incoming transfer">✓ Accept</button>`;
        }
      } else {
        transferActionHtml = `
          <button class="btn-req-transfer" title="Send transfer request">🤝 Request</button>
        `;
      }

      item.innerHTML = `
        <div class="rec-item-user">
          <span class="rec-item-avatar" aria-hidden="true">${initial}</span>
          <span class="rec-item-name">${displayName}</span>
        </div>
        <div class="rec-item-actions" style="display:flex; gap:0.25rem; align-items:center;">
          ${transferActionHtml}
        </div>
      `;

      // Event bindings
      const reqBtn = item.querySelector('.btn-req-transfer');
      if (reqBtn) {
        reqBtn.addEventListener('click', async e => {
          e.stopPropagation();
          await sendTransferRequest(u.username);
        });
      }

      const inlineAcceptBtn = item.querySelector('.btn-inline-accept');
      if (inlineAcceptBtn) {
        inlineAcceptBtn.addEventListener('click', async e => {
          e.stopPropagation();
          await handleAcceptTransfer(inlineAcceptBtn.dataset.id, u.username);
        });
      }

      const msgBtn = item.querySelector('.btn-rec-msg');
      if (msgBtn) {
        msgBtn.addEventListener('click', e => {
          e.stopPropagation();
          closeDropdown();
          selectRecipient(u.username, 'messages');
        });
      }

      const imgBtn = item.querySelector('.btn-rec-img');
      if (imgBtn) {
        imgBtn.addEventListener('click', e => {
          e.stopPropagation();
          closeDropdown();
          selectRecipient(u.username, 'images');
        });
      }

      // Default item click -> Message
      item.addEventListener('click', () => {
        closeDropdown();
        selectRecipient(u.username, 'messages');
      });

      listEl.appendChild(item);
    });

    // If query exists and is not an exact match, still offer quick add
    const exactMatch = _cachedUsers.some(u => (u.username || '').toLowerCase() === q);
    if (q && !exactMatch && q.length >= 3) {
      const quickDiv = document.createElement('div');
      quickDiv.className = 'rec-dropdown-empty';
      quickDiv.style.cssText = 'border-top: 1px dashed var(--glass-border); margin-top:0.3rem; padding: 0.4rem 0.6rem;';
      quickDiv.innerHTML = `
        <button type="button" class="btn btn-xs btn-ghost" id="btn-quick-new" style="color:var(--blue-light); font-size:0.73rem; width:100%; text-align:left;">
          ➕ Or register "<strong>${escHtml(q)}</strong>"
        </button>
      `;
      listEl.appendChild(quickDiv);
      quickDiv.querySelector('#btn-quick-new').addEventListener('click', e => {
        e.stopPropagation();
        closeDropdown();
        openAddModal(q);
      });
    }
  }

  /* ── Open / Close / Toggle ───────────────────────────────────────────────── */
  function openDropdown() {
    _isOpen = true;
    const dd = dom.dropdown();
    if (dd) dd.classList.remove('hidden');
    const bd = dom.backdrop();
    if (bd) bd.classList.remove('hidden');
    const toggleBtn = dom.toggleBtn();
    if (toggleBtn) toggleBtn.classList.add('active');

    const currentVal = dom.panelInput() ? dom.panelInput().value : '';
    renderDropdown(currentVal);

    setTimeout(() => {
      const pInput = dom.panelInput();
      if (pInput) {
        pInput.focus();
        pInput.select();
      }
    }, 60);
  }

  function closeDropdown() {
    _isOpen = false;
    const dd = dom.dropdown();
    if (dd) dd.classList.add('hidden');
    const bd = dom.backdrop();
    if (bd) bd.classList.add('hidden');
    const toggleBtn = dom.toggleBtn();
    if (toggleBtn) toggleBtn.classList.remove('active');
  }

  function toggleDropdown() {
    if (_isOpen) {
      closeDropdown();
    } else {
      refreshUsers();
      refreshTransferRequests();
      openDropdown();
    }
  }

  /* ── Select Recipient (Enforces accepted rule) ───────────────────────────── */
  async function selectRecipient(username, mode = 'messages') {
    closeDropdown();

    // Check if transfer request is accepted
    const tr = _transferRequests.find(r =>
      (r.peer_username || '').toLowerCase() === username.toLowerCase()
    );
    const isAccepted = tr && tr.status === 'accepted';

    if (!isAccepted) {
      // In white box: keep blank!
      const msgSelect = document.getElementById('msg-recipient');
      if (msgSelect) msgSelect.value = '';
      const imgSelect = document.getElementById('img-recipient');
      if (imgSelect) imgSelect.value = '';

      if (mode === 'images') {
        if (typeof App !== 'undefined' && App.showSection) App.showSection('images');
      } else {
        if (typeof App !== 'undefined' && App.showSection) App.showSection('messages');
      }

      AppToast.show(
        `Cannot select "${username}" — transfer request is not accepted yet! Send a transfer request first.`,
        'warning',
        '⚠️ Transfer Not Accepted'
      );
      return;
    }

    // If accepted -> show the name in the white box!
    if (mode === 'images') {
      if (typeof App !== 'undefined' && App.showSection) {
        App.showSection('images');
      }
      if (typeof ImagesModule !== 'undefined' && ImagesModule.selectRecipient) {
        await ImagesModule.selectRecipient(username);
      }
    } else {
      if (typeof App !== 'undefined' && App.showSection) {
        App.showSection('messages');
      }
      if (typeof MessagesModule !== 'undefined' && MessagesModule.selectRecipient) {
        await MessagesModule.selectRecipient(username);
      }
    }
  }

  /* ── Modal Add / Register Recipient ──────────────────────────────────────── */
  function openAddModal(prefillUsername = '') {
    closeDropdown();
    const modal = dom.modal();
    if (!modal) return;

    dom.uInput().value = prefillUsername || '';
    dom.pInput().value = 'password123'; // Default requested password
    dom.errorEl().hidden = true;
    dom.errorEl().textContent = '';

    modal.classList.remove('hidden');
    setTimeout(() => dom.uInput().focus(), 100);
  }

  function closeAddModal() {
    const modal = dom.modal();
    if (modal) modal.classList.add('hidden');
  }

  async function handleAddRecipientSubmit(e) {
    e.preventDefault();
    const username = (dom.uInput().value || '').trim().toLowerCase();
    const password = dom.pInput().value || '';

    dom.errorEl().hidden = true;

    if (!username || username.length < 3 || username.length > 32) {
      showError('Username must be 3–32 characters');
      return;
    }
    if (!username.replace('_', '').replace('-', '').match(/^[a-z0-9]+$/i)) {
      showError('Username can only contain letters, numbers, _ and -');
      return;
    }
    if (password.length < 8) {
      showError('Password must be at least 8 characters');
      return;
    }

    const btn = dom.submitBtn();
    btn.disabled = true;
    btn.textContent = '⏳ Registering…';

    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        showError(data.error || `Registration failed (${res.status})`);
        btn.disabled = false;
        btn.innerHTML = '<span>➕</span> Register &amp; Select Recipient';
        return;
      }

      closeAddModal();
      btn.disabled = false;
      btn.innerHTML = '<span>➕</span> Register &amp; Select Recipient';

      // Automatically send a transfer request to the newly registered user
      await sendTransferRequest(username);

      // Refresh users and recipient selector across app
      await refreshUsers();
      if (typeof MessagesModule !== 'undefined') {
        await MessagesModule.refreshRecipients();
      }
      if (typeof ImagesModule !== 'undefined') {
        await ImagesModule.refreshRecipients();
      }

      AppToast.show(`Recipient "${username}" registered! Transfer request sent.`, 'success', '🎉 Recipient Added');

    } catch (err) {
      showError('Network error — could not register recipient');
      btn.disabled = false;
      btn.innerHTML = '<span>➕</span> Register &amp; Select Recipient';
    }
  }

  function showError(msg) {
    const el = dom.errorEl();
    el.textContent = msg;
    el.hidden = false;
  }

  /* ── Init ────────────────────────────────────────────────────────────────── */
  function init() {
    // Nav Recipients button click -> Toggle dropdown
    const toggleBtn = dom.toggleBtn();
    if (toggleBtn) {
      toggleBtn.addEventListener('click', e => {
        e.stopPropagation();
        if (!AuthModule.isLoggedIn()) return;
        toggleDropdown();
      });
    }

    // Panel search input inside dropdown
    const panelInput = dom.panelInput();
    if (panelInput) {
      panelInput.addEventListener('click', e => {
        e.stopPropagation();
      });

      panelInput.addEventListener('input', e => {
        renderDropdown(e.target.value);
      });

      panelInput.addEventListener('keydown', e => {
        if (e.key === 'Escape') {
          closeDropdown();
        } else if (e.key === 'Enter') {
          e.preventDefault();
          const firstItem = dom.list().querySelector('.rec-dropdown-item');
          if (firstItem) {
            firstItem.click();
          } else if (panelInput.value.trim().length >= 3) {
            openAddModal(panelInput.value.trim());
          }
        }
      });
    }

    // Panel Add button
    const panelAddBtn = dom.panelAddBtn();
    if (panelAddBtn) {
      panelAddBtn.addEventListener('click', e => {
        e.stopPropagation();
        const currentQ = panelInput ? panelInput.value.trim() : '';
        openAddModal(currentQ);
      });
    }

    // Backdrop click
    const backdrop = dom.backdrop();
    if (backdrop) {
      backdrop.addEventListener('click', e => {
        e.stopPropagation();
        closeDropdown();
      });
    }

    // Explicit close button in dropdown header
    const closeBtn = dom.closeBtn();
    if (closeBtn) {
      closeBtn.addEventListener('click', e => {
        e.stopPropagation();
        closeDropdown();
      });
    }

    // Open Add Modal buttons
    if (dom.openModalBtn()) {
      dom.openModalBtn().addEventListener('click', e => {
        e.stopPropagation();
        const currentQ = panelInput ? panelInput.value.trim() : '';
        openAddModal(currentQ);
      });
    }

    if (dom.quickAddBtn()) {
      dom.quickAddBtn().addEventListener('click', e => {
        e.stopPropagation();
        const currentQ = panelInput ? panelInput.value.trim() : '';
        openAddModal(currentQ);
      });
    }

    // Modal controls
    if (dom.modalBackdrop()) dom.modalBackdrop().addEventListener('click', closeAddModal);
    if (dom.modalClose()) dom.modalClose().addEventListener('click', closeAddModal);
    if (dom.form()) dom.form().addEventListener('submit', handleAddRecipientSubmit);

    // Close dropdown when clicking outside
    document.addEventListener('click', e => {
      const container = dom.container();
      const mobRecBtn = document.getElementById('mob-nav-recipients');
      const mobHeaderBtn = document.getElementById('btn-mobile-rec-search');
      if (mobRecBtn && mobRecBtn.contains(e.target)) return;
      if (mobHeaderBtn && mobHeaderBtn.contains(e.target)) return;
      if (container && !container.contains(e.target)) {
        closeDropdown();
      }
    });

    document.addEventListener('keydown', e => {
      if (e.key === 'Escape') {
        closeDropdown();
        closeAddModal();
      }
    });

    // Ensure dropdown starts closed
    closeDropdown();
  }

  function onLogin() {
    const toggleBtn = dom.toggleBtn();
    if (toggleBtn) toggleBtn.disabled = false;
    closeDropdown();
    refreshUsers();
    refreshTransferRequests();
  }

  function onLogout() {
    const toggleBtn = dom.toggleBtn();
    if (toggleBtn) toggleBtn.disabled = true;
    closeDropdown();
    closeAddModal();
    _cachedUsers = [];
    _transferRequests = [];
  }

  return { init, refreshUsers, refreshTransferRequests, onLogin, onLogout, selectRecipient, openAddModal, toggleDropdown, closeDropdown };

})();