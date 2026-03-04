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

  // Prefer in-memory session (if same instance handles this request)
  let sess = sid && memory.sessions.get(sid);

  // Fallback to cookies if memory missing (different instance)
  if (!sess) {
    const siteId = cookies.site && decodeURIComponent(cookies.site);
    const tagId  = cookies.tag && decodeURIComponent(cookies.tag);
    if (!siteId || !tagId) {
      return res.status(401).json({ ok:false, error:'no_session' });
    }
    sess = { status: 'location_ok', site_id: siteId, tagId };
  }

  if (sess.status !== 'location_ok') return res.status(400).json({ ok:false });

  // Generate 6-digit OTP
  const otp = (Math.floor(100000 + Math.random()*900000)).toString();
  sess.otpHash = await sha256(otp);
  sess.otpExpiry = Date.now() + 2*60*1000; // 2 minutes
  sess.status = 'otp_sent';

  // Keep in memory if we have a sid (best effort)
  if (sid) memory.sessions.set(sid, sess);

  // Mirror OTP info into cookies so /verify-otp can fall back if needed
  res.setHeader('Set-Cookie', [
    `otphash=${sess.otpHash}; Path=/; Secure; SameSite=None; Max-Age=180`,
    `otpexp=${sess.otpExpiry}; Path=/; Secure; SameSite=None; Max-Age=180`,
  ]);

  // TODO: send via org email/SMS (for now, print to logs)
  console.log('DEBUG OTP (replace with real send):', otp);

  return res.json({ ok:true, expires_in:120 });
}

const memory = globalThis.__NHGP_MEM__ || (globalThis.__NHGP_MEM__ = { sessions: new Map(), passes: new Map() });

function parseCookie(c){
  // robust parser that preserves '=' in values
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

async function sha256(s){
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2,'0')).join('');
}

export const config = { api: { bodyParser: { sizeLimit: '256kb' } } };
