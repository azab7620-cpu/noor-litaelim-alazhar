/* ============================================================
   🔒 security.js — وحدة الأمان المشتركة
   ============================================================ */

/* ---------- 1) تنقية المدخلات (Sanitization) ---------- */
function sanitizeInput(str, maxLen = 500) {
    if (str === null || str === undefined) return '';
    let s = String(str).trim();
    // إزالة أكواد HTML/JS الخطرة
    s = s.replace(/[<>]/g, '');
    s = s.replace(/javascript:/gi, '');
    s = s.replace(/on\w+\s*=/gi, '');
    // تحديد الطول
    if (s.length > maxLen) s = s.slice(0, maxLen);
    return s;
}

/* ---------- 2) حماية الإخراج من XSS (Output Validation) ---------- */
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;')
        .replace(/\//g, '&#x2F;');
}

/* ---------- 3) تنقية الروابط (منع javascript: protocol) ---------- */
function sanitizeUrl(url) {
    if (!url) return '';
    const u = String(url).trim();
    if (/^https?:\/\//i.test(u)) return u;
    if (/^data:(image|application\/pdf|video|audio)\//i.test(u)) return u;
    return '';
}

/* ---------- 4) التحقق من قوة الباسورد ---------- */
function validateStrongPassword(pass) {
    const errors = [];
    if (!pass || pass.length < 8) errors.push('8 أحرف على الأقل');
    if (!/[a-z]/.test(pass)) errors.push('حرف إنجليزي صغير');
    if (!/[A-Z]/.test(pass)) errors.push('حرف إنجليزي كبير');
    if (!/[0-9]/.test(pass)) errors.push('رقم واحد على الأقل');
    if (!/[!@#$%^&*()_\-+=\[\]{};:'",.<>\/?\\|`~]/.test(pass)) errors.push('رمز خاص (!@#$...)');
    return errors;
}

/* ---------- 5) تشفير الباسورد (PBKDF2 - Web Crypto API) ---------- */
async function hashPassword(password) {
    const enc = new TextEncoder();
    const saltBytes = crypto.getRandomValues(new Uint8Array(16));
    const saltHex = Array.from(saltBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    const iterations = 100000;
    const keyMaterial = await crypto.subtle.importKey(
        'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' },
        keyMaterial, 256
    );
    const hashHex = Array.from(new Uint8Array(bits))
        .map(b => b.toString(16).padStart(2, '0')).join('');
    return `pbkdf2$${iterations}$${saltHex}$${hashHex}`;
}

async function verifyPassword(password, stored) {
    if (!stored || typeof stored !== 'string') return false;
    // توافق مؤقت مع الباسوردات القديمة (plain) — تتحدث تلقائياً
    if (!stored.startsWith('pbkdf2$')) return password === stored;

    const [, iterStr, saltHex, expectedHash] = stored.split('$');
    const iterations = parseInt(iterStr, 10);
    const saltBytes = new Uint8Array(saltHex.match(/.{2}/g).map(h => parseInt(h, 16)));
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' },
        keyMaterial, 256
    );
    const hashHex = Array.from(new Uint8Array(bits))
        .map(b => b.toString(16).padStart(2, '0')).join('');

    // مقارنة ثابتة الزمن (Constant-time)
    if (hashHex.length !== expectedHash.length) return false;
    let diff = 0;
    for (let i = 0; i < hashHex.length; i++) {
        diff |= hashHex.charCodeAt(i) ^ expectedHash.charCodeAt(i);
    }
    return diff === 0;
}

/* ---------- 6) Captcha رياضي (بدون سيرفر) ---------- */
let _captchaAnswer = 0;
function renderCaptcha(containerId) {
    const a = Math.floor(Math.random() * 9) + 2;
    const b = Math.floor(Math.random() * 9) + 2;
    _captchaAnswer = a + b;
    const box = document.getElementById(containerId);
    if (!box) return;
    box.innerHTML = `
        <label style="font-weight:700; color:#3b0a0a; display:block; margin-bottom:6px;">
            🔐 تحقق: كم يساوي ${a} + ${b}؟
        </label>
        <input type="number" id="${containerId}_input" required
            style="width:100%; padding:11px 14px; border:2px solid #eadacc;
                   border-radius:14px; font-size:13px;">
        <span id="${containerId}_err" style="color:#a00; font-size:12px;"></span>
    `;
}
function validateCaptcha(containerId) {
    const input = document.getElementById(`${containerId}_input`);
    const err = document.getElementById(`${containerId}_err`);
    if (!input) return false;
    if (parseInt(input.value, 10) !== _captchaAnswer) {
        if (err) err.textContent = '❌ إجابة التحقق غير صحيحة';
        renderCaptcha(containerId); // جدّد السؤال
        return false;
    }
    if (err) err.textContent = '';
    return true;
}

/* ---------- 7) تحديد معدل المحاولات (Rate Limiting) ---------- */
function checkRateLimit(key, maxAttempts = 5, windowMs = 15 * 60 * 1000) {
    const k = 'rl_' + key;
    const raw = localStorage.getItem(k);
    const data = raw ? JSON.parse(raw) : { count: 0, first: Date.now(), lockedUntil: 0 };

    if (data.lockedUntil && data.lockedUntil > Date.now()) {
        const mins = Math.ceil((data.lockedUntil - Date.now()) / 60000);
        return { allowed: false, remainingMinutes: mins };
    }
    if (Date.now() - data.first > windowMs) {
        data.count = 0;
        data.first = Date.now();
        data.lockedUntil = 0;
        localStorage.setItem(k, JSON.stringify(data));
    }
    if (data.count >= maxAttempts) {
        data.lockedUntil = Date.now() + windowMs;
        localStorage.setItem(k, JSON.stringify(data));
        return { allowed: false, remainingMinutes: Math.ceil(windowMs / 60000) };
    }
    return { allowed: true };
}
function recordFailedAttempt(key, windowMs = 15 * 60 * 1000) {
    const k = 'rl_' + key;
    const raw = localStorage.getItem(k);
    const data = raw ? JSON.parse(raw) : { count: 0, first: Date.now(), lockedUntil: 0 };
    if (Date.now() - data.first > windowMs) {
        data.count = 0; data.first = Date.now(); data.lockedUntil = 0;
    }
    data.count++;
    localStorage.setItem(k, JSON.stringify(data));
}
function clearRateLimit(key) { localStorage.removeItem('rl_' + key); }

/* ---------- 8) سجل الأخطاء (Logs فقط - مش للمستخدم) ---------- */
function logError(context, error) {
    const entry = {
        time: new Date().toISOString(),
        context: String(context || 'unknown'),
        message: error?.message ? String(error.message) : String(error),
        // لا نكتب stack كامل في الإنتاج لأسباب أمنية
        ua: navigator.userAgent
    };
    // اطبع في console فقط (في production ممكن تبعت لسيرفر logging)
    console.error('[SECURITY-LOG]', entry);
    try {
        const logs = JSON.parse(localStorage.getItem('error_logs') || '[]');
        logs.push(entry);
        if (logs.length > 200) logs.splice(0, logs.length - 200);
        localStorage.setItem('error_logs', JSON.stringify(logs));
    } catch (_) { /* تجاهل */ }
}

/* ---------- 9) غلاف آمن لأي دالة async ---------- */
function safeAsync(fn, userMsg = 'حدث خطأ غير متوقع. حاول لاحقاً.') {
    return async function (...args) {
        try {
            return await fn.apply(this, args);
        } catch (e) {
            logError(fn.name || 'anonymous', e);
            alert(userMsg); // رسالة عامة فقط للمستخدم
        }
    };
}

/* ---------- 10) تحقق عام من صحة البريد والهاتف ---------- */
function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || ''));
}
function isValidEgyptPhone(phone) {
    return /^01[0-9]{9}$/.test(String(phone || ''));
}