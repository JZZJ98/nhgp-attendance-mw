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

// Helper: accept JSON or form POST
async function readCode(req) {
  const ctype = (req.headers['content-type'] || '').toLowerCase();
  if (ctype.includes('application/json')) {
    try {
      const { code } = req.body || {};
      return typeof code === 'string' ? code : '';
    } catch { return ''; }
  }
  if (ctype.includes('application/x-www-form-urlencoded')) {
    // Vercel parses urlencoded into req.body by default when bodyParser is on
    const { code } = req.body || {};
    return typeof code === 'string' ? code : '';
  }
  // Fallback: try req.body as-is
  try {
    const { code } = req.body || {};
    return typeof code === 'string' ? code : '';
  } catch { return ''; }
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

  // <-- NEW: read code from JSON or form
  const code = await readCode(req);
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

  // Optional: mark verified in memory if sid exists
      sizeLimit: '64kb' // Vercel's default parser handles JSON & urlencoded
    }
  }
};
