/**
 * SecureVault — auth.js
 * Login, registration, and session management.
 * Session token is stored in memory only (never written to localStorage
 * or cookies from JavaScript) to reduce XSS-based token theft surface.
 */

'use strict';

const AuthModule = (() => {

  /* ── State ──────────────────────────────────────────────────────────────── */
  let _token    = null;
  let _username = null;
  let _userId   = null;

  /* ── Getters ────────────────────────────────────────────────────────────── */
  const getToken    = () => _token;
  const getUsername = () => _username;
  const getUserId   = () => _userId;
  const isLoggedIn  = () => !!_token;

  /**
   * Return Authorization header value for fetch calls.
   */
  const authHeader = () => ({ Authorization: `Bearer ${_token}` });

  /* ── Helpers ────────────────────────────────────────────────────────────── */
  function _setSession(token, username, userId) {
    _token    = token;
    _username = username;
    _userId   = userId;
  }

  function _clearSession() {
    _token    = null;
    _username = null;
    _userId   = null;
  }

  /* ── Register ───────────────────────────────────────────────────────────── */
  async function register(username, password, confirmPassword) {
    if (!username.trim()) throw new Error('Username is required');
    if (password.length < 8) throw new Error('Password must be at least 8 characters');
    if (password !== confirmPassword) throw new Error('Passwords do not match');

    const res = await fetch('/api/auth/register', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ username: username.trim(), password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Registration failed');
    return data;
  }

  /* ── Login ──────────────────────────────────────────────────────────────── */
  async function login(username, password) {
    if (!username.trim()) throw new Error('Username is required');
    if (!password) throw new Error('Password is required');

    const res = await fetch('/api/auth/login', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ username: username.trim(), password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Login failed');

    _setSession(data.token, data.username, data.user_id);
    return data;
  }

  /* ── Logout ─────────────────────────────────────────────────────────────── */
  async function logout() {
    if (!_token) return;
    try {
      await fetch('/api/auth/logout', {
        method:  'POST',
        headers: authHeader(),
      });
    } catch (_) { /* best-effort */ }
    _clearSession();
  }

  /* ── Fetch users (for recipient dropdown) ───────────────────────────────── */
  async function fetchUsers(acceptedOnly = false) {
    const url = acceptedOnly ? '/api/users?accepted_only=1' : '/api/users';
    const res = await fetch(url, { headers: authHeader() });
    if (!res.ok) return [];
    return res.json();
  }

  /* ── UI Bindings ────────────────────────────────────────────────────────── */
  function bindUI(onLoginSuccess, onLogout) {
    /* Toggle password visibility */
    document.addEventListener('click', e => {
      const btn = e.target.closest('.pw-toggle');
      if (!btn) return;
      const targetId = btn.dataset.target;
      const input    = document.getElementById(targetId);
      if (!input) return;
      input.type = input.type === 'password' ? 'text' : 'password';
      btn.textContent = input.type === 'password' ? '👁' : '🙈';
    });

    /* Auth tabs */
    document.querySelectorAll('.auth-tab').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.auth-tab').forEach(b => {
          b.classList.remove('active');
          b.setAttribute('aria-selected', 'false');
        });
        btn.classList.add('active');
        btn.setAttribute('aria-selected', 'true');

        const form = btn.dataset.form;
        document.getElementById('login-form').classList.toggle('hidden', form !== 'login');
        document.getElementById('register-form').classList.toggle('hidden', form !== 'register');
        _clearErrors();
      });
    });

    /* Login form */
    document.getElementById('login-form').addEventListener('submit', async e => {
      e.preventDefault();
      _clearErrors();
      const username = document.getElementById('login-username').value;
      const password = document.getElementById('login-password').value;
      const btn      = document.getElementById('login-btn');

      btn.disabled    = true;
      btn.textContent = '⏳ Logging in…';
      try {
        await login(username, password);
        onLoginSuccess?.(_username, _userId);
      } catch (err) {
        _showError('login-error', err.message);
      } finally {
        btn.disabled    = false;
        btn.innerHTML   = '<span aria-hidden="true">🔑</span> Login Securely';
      }
    });

    /* Register form */
    document.getElementById('register-form').addEventListener('submit', async e => {
      e.preventDefault();
      _clearErrors();
      const username = document.getElementById('reg-username').value;
      const password = document.getElementById('reg-password').value;
      const confirm  = document.getElementById('reg-confirm').value;
      const btn      = document.getElementById('register-btn');

      btn.disabled    = true;
      btn.textContent = '⏳ Creating account…';
      try {
        await register(username, password, confirm);
        AppToast.show('Account created! Please log in.', 'success');
        // Switch to login tab
        document.querySelector('[data-form="login"]').click();
        document.getElementById('login-username').value = username;
      } catch (err) {
        _showError('register-error', err.message);
      } finally {
        btn.disabled  = false;
        btn.innerHTML = '<span aria-hidden="true">✨</span> Create Account';
      }
    });

    /* Logout */
    document.getElementById('logout-btn').addEventListener('click', async () => {
      await logout();
      onLogout?.();
    });
  }

  function _showError(id, msg) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = msg;
    el.hidden = false;
  }
  function _clearErrors() {
    ['login-error', 'register-error'].forEach(id => {
      const el = document.getElementById(id);
      if (el) { el.textContent = ''; el.hidden = true; }
    });
  }

  return { register, login, logout, fetchUsers, isLoggedIn, getToken, getUsername, getUserId, authHeader, bindUI };

})();
