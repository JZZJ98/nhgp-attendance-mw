// --- CORS helper (top of file) ---
function withCors(req, res) {
  const origin = req.headers.origin || '';
  const allowedOrigin = 'https://JZZJ98.github.io'; // <-- change this

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
  // --- 5B: call helper as first line ---
  if (withCors(req, res)) return;

  if (req.method !== 'POST') return res.status(405).end();
  const sid = parseCookie(req.headers.cookie || '').sid;
  if (!sid || !memory.sessions.has(sid)) return res.status(401).end();
  const { code } = req.body || {};
  const sess = memory.sessions.get(sid);
  if (sess.status !== 'otp_sent') return res.status(400).end();
  if (!code) return res.status(400).end();

  const hash = await sha256(code.toString());
  if (hash !== sess.otpHash || Date.now() > sess.otpExpiry) {
    return res.status(401).json({ ok:false, error:'invalid_or_expired' });
  }

  const jti = cryptoRandom(16);
  const expAt = Date.now() + 2*60*1000;
  memory.passes.set(jti, { site_id: sess.site_id, tagId: sess.tagId, redeemed:false, used:false, expAt });
  sess.status = 'otp_verified'; memory.sessions.set(sid, sess);

  res.writeHead(302, { Location: `/api/r/${jti}` });
  return res.end();
}

const memory = globalThis.__NHGP_MEM__ || (globalThis.__NHGP_MEM__ = { sessions: new Map(), passes: new Map() });
function parseCookie(c){ return Object.fromEntries((c||'').split(';').map(v=>v.trim().split('='))) }
function cryptoRandom(n){ return [...crypto.getRandomValues(new Uint8Array(n))].map(b=>b.toString(16).padStart(2,'0')).join('') }
async function sha256(s){ const d=await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)); return [...new Uint8Array(d)].map(b=>b.toString(16).padStart(2,'0')).join('') }
export const config = { api: { bodyParser: { sizeLimit: '64kb' } } };
