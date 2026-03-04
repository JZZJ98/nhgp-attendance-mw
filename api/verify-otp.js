// --- CORS helper (top of file) ---
function withCors(req, res) {
  const origin = req.headers.origin || '';
  const allowedOrigin = 'https://JZZJ98.github.io'; // <-- your GitHub Pages origin EXACT

  if (origin === allowedOrigin || origin.endsWith('.github.io')) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') { res.status(204).end(); return true; }
  return false;
}

// Raw body reader (if Vercel didn't parse)
function readRaw(req) {
  return new Promise((resolve) => {
    try {
      let data = '';
      req.on('data', (ch) => { data += ch; });
      req.on('end', () => resolve(data));
      req.on('error', () => resolve(''));
    } catch { resolve(''); }
  });
}

// Accept JSON or form POST
async function readCode(req) {
  if (req.body && typeof req.body === 'object') {
    const maybe = req.body.code;
    if (typeof maybe === 'string') return maybe.trim();
  }
  const ctype = (req.headers['content-type'] || '').toLowerCase();
  const raw = await readRaw(req);
  if (!raw) return '';
  if (ctype.includes('application/json')) {
    try { const o = JSON.parse(raw); if (o && typeof o.code === 'string') return o.code.trim(); } catch {}
  }
  if (ctype.includes('application/x-www-form-urlencoded')) {
    try { const p = new URLSearchParams(raw); const v = p.get('code'); if (v) return v.trim(); } catch {}
  }
  try { const p = new URLSearchParams(raw); const v = p.get('code'); if (v) return v.trim(); } catch {}
  return '';
}

// Simple HMAC-like signature using SHA-256(secret + meta)
// meta = `${jti}.${site_id}.${expAt}`
async function signMeta(meta, secret) {
  const data = new TextEncoder().encode(secret + '|' + meta);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

export default async function handler(req, res) {
  try {
    if (withCors(req, res)) return;
    if (req.method !== 'POST') return res.status(405).end();

    const cookies = parseCookie(req.headers.cookie || '');
    const sid = cookies.sid;

    // Prefer memory session
    let sess = sid && memory.sessions.get(sid);
    if (!sess) {
      // Fallback from cookies (from previous steps)
      const siteId = cookies.site && decodeURIComponent(cookies.site);
      const tagId  = cookies.tag && decodeURIComponent(cookies.tag);
      const otpHash = cookies.otphash;
      const otpExpiry = Number(cookies.otpexp || 0);
      if (!siteId || !tagId || !otpHash || !otpExpiry) {
        console.warn('[verify-otp] no_session (cookies missing)');
        return res.status(401).json({ ok:false, error:'no_session' });
      }
      sess = { status: 'otp_sent', site_id: siteId, tagId, otpHash, otpExpiry };
    }

    const code = await readCode(req);
    if (sess.status !== 'otp_sent') return res.status(400).json({ ok:false, error:'bad_state' });
    if (!code) return res.status(400).json({ ok:false, error:'missing_code' });

    const hash = await sha256(code.toString());
    if (hash !== sess.otpHash || Date.now() > sess.otpExpiry) {
      return res.status(401).json({ ok:false, error:'invalid_or_expired' });
    }

    // Mint one-time pass (jti)
    const jti = cryptoRandom(16);
    const expAt = Date.now() + 2 * 60 * 1000; // 2 minutes to redeem
    memory.passes.set(jti, {
      site_id: sess.site_id,
      tagId: sess.tagId,
      redeemed: false,
      used: false,
      expAt
    });

    // Optional: mark verified in memory if sid exists
    if (sid) {
      sess.status = 'otp_verified';
      memory.sessions.set(sid, sess);
    }

    // ---- Cookie fallback for /api/r (in case it runs on a different instance) ----
    const secret = process.env.JWT_SECRET || 'devsecret';
    const meta = `${jti}.${sess.site_id}.${expAt}`;
    const sig  = await signMeta(meta, secret);

    res.setHeader('Set-Cookie', [
      `pass_meta=${encodeURIComponent(meta)}; Path=/; Secure; SameSite=None; Max-Age=180`,
      `pass_sig=${sig}; Path=/; Secure; SameSite=None; Max-Age=180`,
    ]);
    // ------------------------------------------------------------------------------

    // 302 to /api/r/<jti>
    res.writeHead(302, { Location: `/api/r/${jti}` });
    return res.end();
  } catch (e) {
    console.error('[verify-otp] fatal error:', e);
    return res.status(500).json({ ok:false, error:'internal_error' });
  }
}

const memory = globalThis.__NHGP_MEM__ || (
  globalThis.__NHGP_MEM__ = { sessions: new Map(), passes: new Map() }
);

function parseCookie(c){
  const out = {};
  (c || '').split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx+1).trim();
    out[k] = v;
  });
  return out;
}

function cryptoRandom(n){
  return [...crypto.getRandomValues(new Uint8Array(n))]
    .map(b=>b.toString(16).padStart(2,'0')).join('');
}

async function sha256(s){
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map(b=>b.toString(16).padStart(2,'0')).join('');
}

export const config = {
  api: { bodyParser: { sizeLimit: '64kb' } }
};
