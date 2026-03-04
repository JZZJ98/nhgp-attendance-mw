export default async function handler(req, res) {
  try {
    const url = new URL(req.url, `https://${req.headers.host}`);
    const [, , jti] = url.pathname.split('/'); // /api/r/<jti>

    const pass = memory.passes.get(jti);
    if (!pass) return res.status(410).send('Link expired or invalid');
    if (pass.expAt < Date.now()) return res.status(410).send('Link expired');
    if (pass.redeemed) return res.status(409).send('Already used link');

    pass.redeemed = true; memory.passes.set(jti, pass);

    const formUrl = new URL('https://form.gov.sg/69647c83f2170fd29c8fec32');
    formUrl.searchParams.set('jti', jti);
    formUrl.searchParams.set('site_id', pass.site_id);

    res.writeHead(302, { Location: formUrl.toString() });
    return res.end();
  } catch (e) {
    console.error('[r] fatal error:', e);
    return res.status(500).send('Internal error');
  }
}

const memory = globalThis.__NHGP_MEM__ || (globalThis.__NHGP_MEM__ = { sessions: new Map(), passes: new Map() });
