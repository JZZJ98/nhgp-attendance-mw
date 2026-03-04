// --- CORS helper (top of file) ---
function withCors(req, res) {
  const origin = req.headers.origin || '';
  const allowedOrigin = 'https://JZZJ98.github.io'; // <-- your GitHub Pages origin EXACT (no trailing slash)

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

  try {
    const { tagId, lat, lng } = req.body || {};
    if (!tagId || typeof lat !== 'number' || typeof lng !== 'number') {
      return res.status(400).json({ ok: false, error: 'Bad request' });
    }

    // ----- YOUR SITE MAP (add more entries as needed) -----
    const sites = {
      // Toa Payoh example from your earlier index.html
      'SGCLINIC01': { site_id: 'SGCLINIC01', lat: 1.3345499, lng: 103.858986, radius: Number(process.env.ALLOWED_RADIUS_M || 170) },
      // 'SGCLINIC02': { site_id: 'SGCLINIC02', lat: <lat>, lng: <lng>, radius: Number(process.env.ALLOWED_RADIUS_M || 50) },
    };
    // ------------------------------------------------------

    const site = sites[tagId];
    if (!site) return res.status(404).json({ ok: false, error: 'Unknown tag' });

    const dMeters = haversine(lat, lng, site.lat, site.lng);
    if (dMeters > site.radius) {
      return res.status(403).json({ ok: false, error: 'Out of geofence', distance: Math.round(dMeters) });
    }

    // Create short session id (best effort, may hit a different instance later)
    const sessionId = cryptoRandom(16);
    memory.sessions.set(sessionId, { status: 'location_ok', site_id: site.site_id, tagId, createdAt: Date.now() });

    // IMPORTANT: multiple cookies (array) so browser sends them in subsequent calls.
    // - sid: HttpOnly session cookie (used if next call lands on same instance)
    // - site/tag: lightweight context cookies (fallback if next call lands on a different instance)
    res.setHeader('Set-Cookie', [
      `sid=${sessionId}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=600`,
      `site=${encodeURIComponent(site.site_id)}; Path=/; Secure; SameSite=None; Max-Age=600`,
      `tag=${encodeURIComponent(tagId)}; Path=/; Secure; SameSite=None; Max-Age=600`,
    ]);

    return res.json({ ok: true, site_id: site.site_id });
  } catch (e) {
    console.error('[verify-location] error:', e);
    return res.status(500).json({ ok: false });
  }
}

const memory = globalThis.__NHGP_MEM__ || (globalThis.__NHGP_MEM__ = { sessions: new Map(), passes: new Map() });

function cryptoRandom(n){
  return [...crypto.getRandomValues(new Uint8Array(n))].map(b => b.toString(16).padStart(2,'0')).join('');
}
function toRad(x){ return x * Math.PI / 180; }
function haversine(lat1, lon1, lat2, lon2){
  const R = 6371000;
  const dLat = toRad(lat2-lat1), dLon = toRad(lon2-lon1);
  const a = Math.sin(dLat/2)**2 + Math.cos(toRad(lat1))*Math.cos(toRad(lat2))*Math.sin(dLon/2)**2;
  return 2 * R * Math.asin(Math.sqrt(a));
}

export const config = { api: { bodyParser: { sizeLimit: '1mb' } } };
