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
  if (!sid || !memory.sessions.has(sid)) return res.status(401).json({ ok:false });
  const sess = memory.sessions.get(sid);
  if (sess.status !== 'location_ok') return res.status(400).json({ ok:false });

  const otp = (Math.floor(100000 + Math.random()*900000)).toString();
  sess.otpHash = await sha256(otp);
  sess.otpExpiry = Date.now() + 2*60*1000;
  sess.status = 'otp_sent';
  memory.sessions.set(sid, sess);

  // TODO: send via your org’s email/SMS
  console.log('DEBUG OTP (replace with real send):', otp);

  return res.json({ ok:true, expires_in:120 });
}

const memory = globalThis.__NHGP_MEM__ || (globalThis.__NHGP_MEM__ = { sessions: new Map(), passes: new Map() });
function parseCookie(c){ return Object.fromEntries((c||'').split(';').map(v=>v.trim().split('='))) }
async function sha256(s){ const d=await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)); return [...new Uint8Array(d)].map(b=>b.toString(16).padStart(2,'0')).join('') }
export const config = { api: { bodyParser: { sizeLimit: '256kb' } } };
