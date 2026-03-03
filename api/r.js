function withCors(req, res) {
  const origin = req.headers.origin || '';
  const allowedOrigin = 'https://JZZJ98.github.io'; 

  if (origin === allowedOrigin || origin.endsWith('.github.io')) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }

  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');

  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return true;
  }

  return false;
}

export default async function handler(req, res) {
  const url = new URL(req.url, `https://${req.headers.host}`);
  const [, , jti] = url.pathname.split('/'); // /api/r/<jti>

  const pass = memory.passes.get(jti);
  if (!pass || pass.expAt < Date.now()) return res.status(410).send('Link expired');
  if (pass.redeemed) return res.status(409).send('Already used link');

  pass.redeemed = true; memory.passes.set(jti, pass);

  const formUrl = new URL('https://form.gov.sg/69647c83f2170fd29c8fec32'); // YOUR live FormSG URL
  formUrl.searchParams.set('jti', jti);
  formUrl.searchParams.set('site_id', pass.site_id);

  res.writeHead(302, { Location: formUrl.toString() });
  return res.end();
}

const memory = globalThis.__NHGP_MEM__ || (globalThis.__NHGP_MEM__ = { sessions: new Map(), passes: new Map() });
