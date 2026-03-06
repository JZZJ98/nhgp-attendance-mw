import formsgSDK from '@opengovsg/formsg-sdk'; // you pinned ^0.15.0 in package.json

// Instantiate SDK for production; enables signature verification & decrypt helpers
const formsg = formsgSDK({ mode: 'production' });

// Map responses to key->value by field name (title)
function pickResponses(responses = []) {
  const out = {};
  for (const r of responses) {
    if (r && typeof r.name === 'string') out[r.name] = r.answer;
  }
  return out;
}

// Same sign helper used elsewhere: SHA-256(secret | meta)
async function signMeta(meta, secret) {
  const data = new TextEncoder().encode(secret + '|' + meta);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

export default async function handler(req, res) {
  try {
    if (req.method !== 'POST') return res.status(405).end();

    const signature = req.headers['x-formsg-signature'];
    const postUri   = process.env.FORMSG_WEBHOOK_URI;
    const formSecretKey = process.env.FORM_SECRET_KEY;
    const jwtSecret = process.env.JWT_SECRET || 'devsecret';

    console.log('[webhook] hit', req.method,
      'sig?', !!signature,
      'has data?', !!req.body?.data
    );
    console.log('[webhook] env ok?',
      !!formSecretKey,
      !!postUri
    );

    if (!signature || !postUri || !formSecretKey) {
      console.error('[webhook] missing env or signature header');
      return res.status(200).json({ ok: true, status: 'missing_config' });
    }

    // 1) Verify signed webhook (official SDK)
    try {
      formsg.webhooks.authenticate(signature, postUri);
    } catch (err) {
      console.warn('[webhook] invalid_signature');
      return res.status(200).json({ ok: true, status: 'invalid_signature' });
    }

    // 2) Decrypt submission (official SDK)
    const encrypted = req.body?.data;
    if (!encrypted) {
      console.warn('[webhook] missing_payload');
      return res.status(200).json({ ok: true, status: 'missing_payload' });
    }

    let decrypted;
    try {
      decrypted = await formsg.crypto.decrypt(encrypted, formSecretKey);
    } catch (err) {
      console.error('[webhook] decrypt_failed', err);
      return res.status(200).json({ ok: true, status: 'decrypt_failed' });
    }

    const map = pickResponses(decrypted.responses);
    const jti = map['jti'];
    const siteId = map['site_id'];
    const gate = map['gate'];
    const expStr = map['exp'];

    console.log('[webhook] fields:', { jti, site_id: siteId, gate, exp: expStr });

    if (!jti || !siteId || !gate || !expStr) {
      console.warn('[webhook] missing_hidden_fields');
      return res.status(200).json({ ok: true, status: 'missing_hidden_fields' });
    }

    const expAt = Number(expStr);
    if (!Number.isFinite(expAt) || Date.now() > expAt) {
      console.warn('[webhook] expired_gate', { jti, siteId, expAt });
      return res.status(200).json({ ok: true, status: 'expired_gate' });
    }

    const meta = `${jti}.${siteId}.${expAt}`;
    const sigCheck = await signMeta(meta, jwtSecret);
    if (sigCheck !== gate) {
      console.warn('[webhook] bad_gate_signature', { jti, siteId });
      return res.status(200).json({ ok: true, status: 'bad_gate_signature' });
    }

    // (Optional: If you move to Redis later, mark jti used here)

    console.log('[webhook] ACCEPT via gate', {
      formId: decrypted.formId,
      submissionId: decrypted.submissionId,
      jti,
      siteId
    });
    return res.status(200).json({ ok: true, status: 'accepted_gate' });
  } catch (err) {
    console.error('[webhook] fatal error:', err);
    // Always 200 to avoid retries for malformed/spoofed calls
    return res.status(200).json({ ok: true, status: 'internal_error' });
  }
}

// In-memory fallback (demo)
const memory = globalThis.__NHGP_MEM__ || (
  globalThis.__NHGP_MEM__ = { sessions: new Map(), passes: new Map() }
);

export const config = { api: { bodyParser: { sizeLimit: '2mb' } } };
