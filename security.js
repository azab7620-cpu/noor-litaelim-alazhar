// ============================================================
//  security.js — أدوات الأمان المشتركة
//  نور تعليم الأزهر
// ============================================================
const Security = (() => {
    // ---------- 1) تسجيل الأخطاء (في الكونسول فقط، لا تظهر للمستخدم) ----------
    function logError(context, err) {
        const payload = {
            ts: new Date().toISOString(),
            context,
            message: err?.message || String(err),
        };
        console.error('[SEC]', payload);
        // لو عندك خدمة logging خارجية لاحقاً، ابعت هنا.
    }
    function safeHandler(context, fn) {
        return async (...args) => {
            try { return await fn(...args); }
            catch (e) { logError(context, e); return null; }
        };
    }

    // ---------- 2) تعقيم المدخلات ----------
    function sanitizeString(input, maxLen = 200) {
        if (input == null) return '';
        let s = String(input).replace(/[\u0000-\u001F\u007F]/g, '');
        return s.trim().slice(0, maxLen);
    }
    function escapeHTML(str) {
        if (str == null) return '';
        return String(str)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;').replace(/\//g, '&#x2F;');
    }
    function sanitizeEmail(email) {
        const e = sanitizeString(email, 120).toLowerCase();
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) ? e : null;
    }
    function sanitizePhone(phone) {
        const p = sanitizeString(phone, 20).replace(/[^\d+]/g, '');
        return /^\+?\d{8,15}$/.test(p) ? p : null;
    }
    function sanitizeUrl(url) {
        const u = sanitizeString(url, 2048);
        if (!u) return null;
        return /^(https?:\/\/|data:)/i.test(u) ? u : null;
    }

    // ---------- 3) قوة كلمة المرور ----------
    const PW_RULES = [
        { test: s => s.length >= 10,         msg: '10 أحرف على الأقل' },
        { test: s => /[A-Z]/.test(s),        msg: 'حرف كبير (A-Z)' },
        { test: s => /[a-z]/.test(s),        msg: 'حرف صغير (a-z)' },
        { test: s => /\d/.test(s),           msg: 'رقم (0-9)' },
        { test: s => /[^A-Za-z0-9]/.test(s), msg: 'رمز خاص (!@#$…)' },
    ];
    function validateStrongPassword(pw) {
        const failures = PW_RULES.filter(r => !r.test(pw)).map(r => r.msg);
        return { valid: failures.length === 0, failures };
    }
    function passwordStrengthScore(pw) {
        if (!pw) return 0;
        let s = 0; PW_RULES.forEach(r => { if (r.test(pw)) s++; });
        if (pw.length >= 14) s++;
        return Math.min(s, 5);
    }

    // ---------- 4) Hash للباسورد (PBKDF2-SHA256, 150k iterations) ----------
    async function generateSalt(bytes = 16) {
        const arr = new Uint8Array(bytes);
        crypto.getRandomValues(arr);
        return [...arr].map(b => b.toString(16).padStart(2, '0')).join('');
    }
    async function hashPassword(password, saltHex) {
        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
        );
        const salt = new Uint8Array(saltHex.match(/.{2}/g).map(h => parseInt(h, 16)));
        const bits = await crypto.subtle.deriveBits(
            { name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' },
            keyMaterial, 256
        );
        return [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, '0')).join('');
    }
    async function createPasswordRecord(password) {
        const salt = await generateSalt();
        const hash = await hashPassword(password, salt);
        return { salt, hash, algo: 'PBKDF2-SHA256-150k' };
    }
    async function verifyPassword(password, record) {
        if (!record?.salt || !record?.hash) return false;
        const h = await hashPassword(password, record.salt);
        if (h.length !== record.hash.length) return false;
        let diff = 0;
        for (let i = 0; i < h.length; i++) diff |= h.charCodeAt(i) ^ record.hash.charCodeAt(i);
        return diff === 0;
    }

    // ---------- 5) Rate Limiting لتسجيل الدخول ----------
    const RL_KEY = 'nour_rl_v1';
    const RL_MAX = 5, RL_WINDOW = 15 * 60 * 1000, RL_LOCK = 15 * 60 * 1000;
    const _load = () => { try { return JSON.parse(localStorage.getItem(RL_KEY)) || {}; } catch { return {}; } };
    const _save = o => { try { localStorage.setItem(RL_KEY, JSON.stringify(o)); } catch {} };

    function checkRateLimit(id) {
        const now = Date.now();
        const store = _load();
        const r = store[id] || { attempts: [], lockedUntil: 0 };
        if (r.lockedUntil > now) return { allowed: false, retryAfterMs: r.lockedUntil - now };
        r.attempts = (r.attempts || []).filter(t => now - t < RL_WINDOW);
        store[id] = r; _save(store);
        return { allowed: true, remaining: RL_MAX - r.attempts.length };
    }
    function recordFailedAttempt(id) {
        const now = Date.now();
        const store = _load();
        const r = store[id] || { attempts: [], lockedUntil: 0 };
        r.attempts = (r.attempts || []).filter(t => now - t < RL_WINDOW);
        r.attempts.push(now);
        if (r.attempts.length >= RL_MAX) { r.lockedUntil = now + RL_LOCK; r.attempts = []; }
        store[id] = r; _save(store);
    }
    function clearRateLimit(id) { const s = _load(); delete s[id]; _save(s); }

    // ---------- 6) CAPTCHA (رياضي بسيط — للاستخدام الحقيقي استعمل reCAPTCHA) ----------
    const CAP_KEY = 'nour_cap_v1';
    function generateCaptcha() {
        const a = Math.floor(Math.random() * 9) + 2;
        const b = Math.floor(Math.random() * 9) + 2;
        const op = Math.random() < 0.5 ? '+' : '×';
        const answer = op === '+' ? a + b : a * b;
        const token = crypto.getRandomValues(new Uint32Array(2)).join('-');
        sessionStorage.setItem(CAP_KEY, JSON.stringify({
            token, answer, expires: Date.now() + 5 * 60 * 1000
        }));
        return { question: `${a} ${op} ${b} = ؟`, token };
    }
    function verifyCaptcha(userAnswer) {
        try {
            const st = JSON.parse(sessionStorage.getItem(CAP_KEY) || 'null');
            sessionStorage.removeItem(CAP_KEY);
            if (!st || Date.now() > st.expires) return false;
            return parseInt(userAnswer, 10) === st.answer;
        } catch { return false; }
    }

    // ---------- 7) إخراج آمن ----------
    function setText(el, text) { if (el) el.textContent = sanitizeString(text, 500); }
    function safeAttr(v) { return escapeHTML(v).replace(/`/g, '&#96;'); }

    return {
        logError, safeHandler,
        sanitizeString, escapeHTML, sanitizeEmail, sanitizePhone, sanitizeUrl,
        validateStrongPassword, passwordStrengthScore,
        generateSalt, hashPassword, createPasswordRecord, verifyPassword,
        checkRateLimit, recordFailedAttempt, clearRateLimit,
        generateCaptcha, verifyCaptcha,
        setText, safeAttr
    };
})();
window.Security = Security;