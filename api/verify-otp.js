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

export default async function handler(req, res) {
  if (withCors(req, res)) return;
  if (req.method !== 'POST') return res.status(405).end();

  const cookies = parseCookie(req.headers.cookie || '');
  const sid = cookies.sid;

  // Prefer memory session if present
  let sess = sid && memory.sessions.get(sid);

  // Fallback from cookies if memory missing
  if (!sess) {
    const siteId = cookies.site && decodeURIComponent(cookies.site);
    const tagId  = cookies.tag && decodeURIComponent(cookies.tag);
    const otpHash = cookies.otphash;
    const otpExpiry = Number(cookies.otpexp || 0);
    if (!siteId || !tagId || !otpHash || !otpExpiry) {
      return res.status(401).json({ ok:false, error:'no_session' });
    }
    sess = { status: 'otp_sent', site_id: siteId, tagId, otpHash, otpExpiry };
  }

  const { code } = req.body || {};
  if (sess.status !== 'otp_sent') return res.status(400).end();
  if (!code) return res.status(400).end();

  const hash = await sha256(code.toString());
  if (hash !== sess.otpHash || Date.now() > sess.otpExpiry) {
    return res.status(401).json({ ok:false, error:'invalid_or_expired' });
  }

  // create one-time pass jti
  const jti = cryptoRandom(16);
  const expAt = Date.now() + 2*60*1000; // 2 minutes to redeem
  memory.passes.set(jti, { site_id: sess.site_id, tagId: sess.tagId, redeemed:false, used:false, expAt });

  // If we had a sid/memory, you may mark verified (optional)
  if (sid) {
    sess.status = 'otp_verified';
    memory.sessions.set(sid, sess);
  }

  // 302 redirect to one-time redirect endpoint
  res.writeHead(302, { Location: `/api/r/${jti}` });
  return res.end();
}

const memory = globalThis.__NHGP_MEM__ || (globalThis.__NHGP_MEM__ = { sessions: new Map(), passes: new Map() });

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
  return [...crypto.getRandomValues(new Uint8Array(n))].map(b=>b.toString(16).padStart(2,'0')).join('');
}

async function sha256(s){
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map(b=>b.toString(16).padStart(2,'0')).join('');
}

export const config = { api: { bodyParser: { sizeLimit: '64kb' } } };
