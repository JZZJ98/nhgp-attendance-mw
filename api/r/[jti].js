export default async function handler(req, res) {
  try {
    // Vercel provides dynamic path params on req.query
    const { jti } = req.query || {};
    if (!jti) return res.status(400).send('Missing token');

    const pass = memory.passes.get(jti);
    if (!pass) return res.status(410).send('Link expired or invalid');
    if (pass.expAt < Date.now()) return res.status(410).send('Link expired');
    if (pass.redeemed) return res.status(409).send('Already used link');

    // Mark redeemed atomically
    pass.redeemed = true;
    memory.passes.set(jti, pass);

    // Redirect to your live FormSG form with hidden fields prefilled
    const formUrl = new URL('https://form.gov.sg/69647c83f2170fd29c8fec32');
    formUrl.searchParams.set('jti', jti);
    formUrl.searchParams.set('site_id', pass.site_id);

    res.writeHead(302, { Location: formUrl.toString() });
    return res.end();
  } catch (e) {
    console.error('[r/[jti]] fatal error:', e);
    return res.status(500).send('Internal error');
  }
}

// Use a shared in-memory object (demo only). For production, move to Redis/KV.
const memory = globalThis.__NHGP_MEM__ || (
  globalThis.__NHGP_MEM__ = { sessions: new Map(), passes: new Map() }
);
