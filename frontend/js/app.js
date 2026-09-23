/**
 * SecureVault — app.js
 * Main application controller: SPA routing, tab navigation, header state,
 * toast system, particle canvas background, and module wiring.
 */

'use strict';

/* ═══════════════════════════════════════════════════════════════════════════
   Toast Notification System
   ═══════════════════════════════════════════════════════════════════════════ */
const AppToast = (() => {
  const container = () => document.getElementById('toast-container');

  const ICONS = {
    success: '✅',
    error: '❌',
    warning: '⚠️',
    info: 'ℹ️',
  };

  /**
   * Show a toast notification.
   * @param {string} message
   * @param {'success'|'error'|'warning'|'info'} type
   * @param {string} [title]
   * @param {number} [duration=4000]
   */
  function show(message, type = 'info', title = '', duration = 4000) {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
      <span class="toast-icon" aria-hidden="true">${ICONS[type] || 'ℹ️'}</span>
      <div class="toast-body">
        ${title ? `<div class="toast-title">${escHtml(title)}</div>` : ''}
        <div class="toast-msg">${escHtml(message)}</div>
      </div>
    `;
    container().appendChild(toast);
    setTimeout(() => remove(toast), duration);
  }

  function remove(el) {
    el.classList.add('removing');
    el.addEventListener('animationend', () => el.remove(), { once: true });
  }

  return { show };
})();


/* ═══════════════════════════════════════════════════════════════════════════
   Particle Canvas Background
   ═══════════════════════════════════════════════════════════════════════════ */
function initCanvas() {
  const canvas = document.getElementById('bg-canvas');
  const ctx = canvas.getContext('2d');
  let W, H, particles;

  const PARTICLE_COUNT = 45;
  const MAX_DIST = 110;
  const COLORS = ['#3b82f6', '#64748b', '#60a5fa', '#2563eb'];

  function resize() {
    W = canvas.width = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }

  function mkParticle() {
    return {
      x: Math.random() * W,
      y: Math.random() * H,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
      r: Math.random() * 1.8 + 0.8,
      color: COLORS[Math.floor(Math.random() * COLORS.length)],
    };
  }

  function init() {
    resize();
    particles = Array.from({ length: PARTICLE_COUNT }, mkParticle);
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);

    // Update & draw particles (subtle 15% opacity)
    for (const p of particles) {
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0 || p.x > W) p.vx *= -1;
      if (p.y < 0 || p.y > H) p.vy *= -1;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = p.color;
      ctx.globalAlpha = 0.15;
      ctx.fill();
    }

    // Draw connecting lines (subtle 6-8% opacity)
    ctx.globalAlpha = 1;
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const a = particles[i], b = particles[j];
        const dx = a.x - b.x, dy = a.y - b.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < MAX_DIST) {
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.strokeStyle = a.color;
          ctx.globalAlpha = (1 - dist / MAX_DIST) * 0.07;
          ctx.lineWidth = 0.75;
          ctx.stroke();
        }
      }
    }
    requestAnimationFrame(draw);
  }

  window.addEventListener('resize', resize);
  init();
  draw();
}


/* ═══════════════════════════════════════════════════════════════════════════
   SPA Router & Tab Navigation
   ═══════════════════════════════════════════════════════════════════════════ */
const App = (() => {

  const SECTIONS = {
    auth: 'section-auth',
    messages: 'section-messages',
    images: 'section-images',
    security: 'section-security',
  };

  let _activeTab = 'auth';

  /* ── Show section ──────────────────────────────────────────────────────── */
  function showSection(id) {
    Object.values(SECTIONS).forEach(secId => {
      const el = document.getElementById(secId);
      if (el) el.classList.toggle('hidden', secId !== SECTIONS[id]);
    });
    // Sync desktop top nav buttons (excluding recipient dropdown toggle)
    document.querySelectorAll('.nav-btn[data-tab]').forEach(btn => {
      if (btn.dataset.tab !== 'recipients') {
        btn.classList.toggle('active', btn.dataset.tab === id);
      }
    });
    // Sync mobile bottom nav buttons
    document.querySelectorAll('.mobile-nav-btn[data-tab]').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.tab === id);
    });
    _activeTab = id;

    // Notify modules on activation
    if (id === 'messages') MessagesModule.onActivate();
    if (id === 'images') ImagesModule.onActivate();
    if (id === 'security') loadAuditLog();
  }

  /* ── Auth state update ─────────────────────────────────────────────────── */
  function setLoggedIn(username) {
    // Enable nav buttons
    document.querySelectorAll('.nav-btn').forEach(b => b.disabled = false);
    document.querySelectorAll('.mobile-nav-btn').forEach(b => b.disabled = false);

    // Update body state
    document.body.classList.remove('logged-out');
    document.body.classList.add('logged-in');

    // Show mobile bottom nav
    const mobNav = document.getElementById('mobile-bottom-nav');
    if (mobNav) mobNav.classList.remove('hidden');

    // Show mobile header search toggle
    const mobSearch = document.getElementById('btn-mobile-rec-search');
    if (mobSearch) mobSearch.style.display = '';

    // Show user chip & logout
    const chip = document.getElementById('user-chip');
    chip.style.display = '';
    document.getElementById('logout-btn').style.display = '';
    document.getElementById('header-username').textContent = username;
    document.getElementById('user-avatar').textContent = username.charAt(0).toUpperCase();

    showSection('messages');
    if (typeof RecipientSearchModule !== 'undefined') {
      RecipientSearchModule.onLogin();
    }
    AppToast.show(`Welcome back, ${username}!`, 'success', '🔐 Signed In');
  }

  function setLoggedOut() {
    document.querySelectorAll('.nav-btn').forEach(b => b.disabled = true);
    document.querySelectorAll('.mobile-nav-btn').forEach(b => b.disabled = true);

    // Update body state
    document.body.classList.remove('logged-in');
    document.body.classList.add('logged-out');

    // Hide mobile bottom nav
    const mobNav = document.getElementById('mobile-bottom-nav');
    if (mobNav) mobNav.classList.add('hidden');

    // Hide mobile header search toggle
    const mobSearch = document.getElementById('btn-mobile-rec-search');
    if (mobSearch) mobSearch.style.display = 'none';

    document.getElementById('user-chip').style.display = 'none';
    document.getElementById('logout-btn').style.display = 'none';
    if (typeof RecipientSearchModule !== 'undefined') {
      RecipientSearchModule.onLogout();
    }
    showSection('auth');
    AppToast.show('You have been signed out', 'info');
  }

  /* ── Audit log ─────────────────────────────────────────────────────────── */
  let _auditFilter = 'all';
  let _rawAuditEvents = [];

  function renderAuditLog() {
    const el = document.getElementById('audit-log');
    if (!el) return;

    let filtered = _rawAuditEvents;
    if (_auditFilter === 'auth') {
      filtered = _rawAuditEvents.filter(e =>
        ['LOGIN', 'LOGOUT', 'USER_REGISTERED'].some(k => (e.event_type || '').includes(k))
      );
    } else if (_auditFilter === 'content') {
      filtered = _rawAuditEvents.filter(e =>
        ['MESSAGE', 'IMAGE', 'TRANSFER'].some(k => (e.event_type || '').includes(k))
      );
    }

    if (!filtered.length) {
      const msg = _auditFilter === 'all'
        ? '📋 No security events yet'
        : `📋 No ${_auditFilter === 'auth' ? 'Login/Sign Out' : 'Message/Image'} events found`;
      el.innerHTML = `<div class="empty-state">${msg}</div>`;
      return;
    }

    el.innerHTML = '';
    filtered.forEach(evt => {
      const row = document.createElement('div');
      row.className = 'audit-row';
      const d = new Date(evt.created_at + 'Z');
      const timeStr = d.toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'medium' });
      row.innerHTML = `
        <div class="audit-event">${escHtml(evt.event_type)}</div>
        <div class="audit-time">${timeStr}</div>
        <div class="audit-result ${escHtml(evt.result)}">${escHtml(evt.result)}</div>
      `;
      el.appendChild(row);
    });
  }

  async function loadAuditLog() {
    const el = document.getElementById('audit-log');
    if (el) el.innerHTML = '<div class="loading-placeholder">Loading audit events (max 20)…</div>';
    try {
      const res = await fetch('/api/security/events', { headers: AuthModule.authHeader() });
      if (!res.ok) {
        if (el) el.innerHTML = '<div class="empty-state">Unable to load events</div>';
        return;
      }
      _rawAuditEvents = await res.json();
      renderAuditLog();
    } catch (_) {
      if (el) el.innerHTML = '<div class="empty-state">Error loading events</div>';
    }
  }

  async function clearAuditLog() {
    if (!confirm('Clear all security audit log events?\n\nThis permanently removes recorded audit entries.')) return;
    try {
      const res = await fetch('/api/security/events', {
        method: 'DELETE',
        headers: AuthModule.authHeader(),
      });
      if (!res.ok) {
        AppToast.show('Could not clear audit log', 'error');
        return;
      }
      AppToast.show('Security audit log cleared', 'info', '🗑 Cleared');
      await loadAuditLog();
    } catch (_) {
      AppToast.show('Network error while clearing audit log', 'error');
    }
  }

  /* ── Init ──────────────────────────────────────────────────────────────── */
  function init() {
    // Canvas particles
    initCanvas();

    // Nav buttons
    document.querySelectorAll('.nav-btn[data-tab]').forEach(btn => {
      btn.addEventListener('click', () => {
        if (!AuthModule.isLoggedIn()) return;
        if (btn.dataset.tab === 'recipients') return;
        showSection(btn.dataset.tab);
      });
    });

    // Audit refresh & clear
    const refBtn = document.getElementById('refresh-audit');
    if (refBtn) refBtn.addEventListener('click', loadAuditLog);

    const clearBtn = document.getElementById('btn-clear-audit');
    if (clearBtn) clearBtn.addEventListener('click', clearAuditLog);

    // Audit filter tabs
    ['all', 'auth', 'content'].forEach(filterKey => {
      const tab = document.getElementById(`audit-tab-${filterKey}`);
      if (tab) {
        tab.addEventListener('click', () => {
          _auditFilter = filterKey;
          ['all', 'auth', 'content'].forEach(k => {
            const t = document.getElementById(`audit-tab-${k}`);
            if (t) {
              t.classList.toggle('active', k === filterKey);
              t.setAttribute('aria-selected', String(k === filterKey));
            }
          });
          renderAuditLog();
        });
      }
    });

    // Wire auth module
    AuthModule.bindUI(
      (username) => setLoggedIn(username),
      () => setLoggedOut()
    );

    // Wire message module
    MessagesModule.init();

    // Wire images module
    ImagesModule.init();

    // Wire recipient search & add module
    if (typeof RecipientSearchModule !== 'undefined') {
      RecipientSearchModule.init();
    }

    // Wire mobile navigation buttons
    document.querySelectorAll('.mobile-nav-btn[data-tab]').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.dataset.tab;
        if (tab && !btn.disabled) showSection(tab);
      });
    });

    const mobRecBtn = document.getElementById('mob-nav-recipients');
    if (mobRecBtn) {
      mobRecBtn.addEventListener('click', e => {
        e.stopPropagation();
        if (typeof RecipientSearchModule !== 'undefined') {
          RecipientSearchModule.toggleDropdown();
        }
      });
    }

    const mobHeaderSearchBtn = document.getElementById('btn-mobile-rec-search');
    if (mobHeaderSearchBtn) {
      mobHeaderSearchBtn.addEventListener('click', e => {
        e.stopPropagation();
        if (typeof RecipientSearchModule !== 'undefined') {
          RecipientSearchModule.toggleDropdown();
        }
      });
    }

    // Wire responsive layout module (media queries + viewport detection)
    ResponsiveLayoutModule.init();

    // Start on auth section
    showSection('auth');
  }

  return { init, showSection };
})();


/* ═══════════════════════════════════════════════════════════════════════════
   Responsive Layout Module (Viewport Detection & Adaptive Layouts)
   - Automatically adapts between normal mobile and desktop layouts
   - Accurately detects "Desktop Site" on mobile browsers without forcing mobile layout
   - Seamlessly reacts to viewport changes and orientation changes
   ═══════════════════════════════════════════════════════════════════════════ */
const ResponsiveLayoutModule = (() => {
  let _resizeTimer = null;

  /**
   * Detect current layout and device characteristics from viewport and screen metrics
   */
  function detectLayoutState() {
    const width = window.innerWidth || document.documentElement.clientWidth || 1024;
    const height = window.innerHeight || document.documentElement.clientHeight || 768;
    const screenWidth = window.screen ? (window.screen.width || width) : width;
    const hasTouch = ('ontouchstart' in window) || (navigator.maxTouchPoints > 0);
    const ua = navigator.userAgent || '';
    const hasMobileUA = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini|Mobile/i.test(ua);

    // Characteristic check for mobile browser with "Desktop Site" enabled:
    const isDesktopSite = (hasTouch || hasMobileUA) && (width >= 980 || width > screenWidth);

    // <= 768px: Mobile layout
    // > 768px: Desktop layout (including Desktop Site at 980px+)
    const isMobileViewport = width <= 768;
    const layout = isMobileViewport ? 'mobile' : 'desktop';

    return {
      layout,
      isDesktopSite,
      isMobileViewport,
      width,
      height,
      hasTouch,
    };
  }

  /**
   * Apply layout classes & dataset attributes
   */
  function applyLayout() {
    const state = detectLayoutState();
    const rootEl = document.documentElement;

    rootEl.dataset.layout = state.layout;
    rootEl.dataset.desktopSite = String(state.isDesktopSite);
  }

  function init() {
    applyLayout();

    // Window resize listener with debouncing
    window.addEventListener('resize', () => {
      if (_resizeTimer) cancelAnimationFrame(_resizeTimer);
      _resizeTimer = requestAnimationFrame(applyLayout);
    });

    // Media query change listener for instant breakpoint crossing
    const mql = window.matchMedia('(max-width: 768px)');
    if (mql.addEventListener) {
      mql.addEventListener('change', applyLayout);
    }

    // Orientation change listener
    if (window.screen && window.screen.orientation) {
      window.screen.orientation.addEventListener('change', () => {
        setTimeout(applyLayout, 100);
      });
    } else {
      window.addEventListener('orientationchange', () => {
        setTimeout(applyLayout, 100);
      });
    }
  }

  return {
    init,
    detectLayoutState,
    applyLayout,
  };
})();


/* ═══════════════════════════════════════════════════════════════════════════
   Boot
   ═══════════════════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => App.init());
