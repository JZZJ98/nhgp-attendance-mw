import formsgSDK from '@opengovsg/formsg-sdk' // v0.15.0 as in your package.json

// Instantiate SDK for production; this enables signature verification and decryption helpers
const formsg = formsgSDK({ mode: 'production' })

// Helper: parse FormSG decrypted responses into a simple key->value map
function pickResponses(responses = []) {
  const out = {}
  for (const r of responses) {
    // Each r has { _id, fieldType, question, answer, ... } ; we rely on "name" (i.e. field title)
    // Hidden Short Text fields we need are: jti, site_id, gate, exp
    if (r && typeof r.name === 'string') {
      out[r.name] = r.answer
    }
  }
  return out
}

// Same signing approach we used elsewhere: HMAC-like hash using SHA-256(secret + '|' + meta)
// meta format: `${jti}.${site_id}.${exp}` (exp is a unix ms timestamp)
async function signMeta(meta, secret) {
  const data = new TextEncoder().encode(secret + '|' + meta)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('')
}

export default async function handler(req, res) {
  try {
    if (req.method !== 'POST') return res.status(405).end()

    const signature = req.headers['x-formsg-signature']
    const postUri = process.env.FORMSG_WEBHOOK_URI
    const formSecretKey = process.env.FORM_SECRET_KEY
    const jwtSecret = process.env.JWT_SECRET || 'devsecret'

    if (!signature || !postUri || !formSecretKey) {
      console.error('[webhook] missing env or signature header')
      // Ack 200 to prevent retries, but flag in logs
      return res.status(200).json({ ok: true, status: 'missing_config' })
    }

    // 1) Verify the webhook signature (throws if invalid)
    try {
      formsg.webhooks.authenticate(signature, postUri)
    } catch (err) {
      console.warn('[webhook] invalid signature')
      return res.status(200).json({ ok: true, status: 'invalid_signature' })
    }

    // 2) Decrypt the submission payload
    // Raw POST body is expected to be JSON with { data: <encrypted payload> }
    const encrypted = req.body?.data
    if (!encrypted) {
      console.warn('[webhook] missing encrypted payload')
      return res.status(200).json({ ok: true, status: 'missing_payload' })
    }

    let decrypted
    try {
      decrypted = await formsg.crypto.decrypt(encrypted, formSecretKey)
      // shape: { formId, submissionId, responses: [...], verified?: {...}, ... }
    } catch (err) {
      console.error('[webhook] decrypt failed:', err)
      return res.status(200).json({ ok: true, status: 'decrypt_failed' })
    }

    const map = pickResponses(decrypted.responses)
    const jti = map['jti']
    const siteId = map['site_id']
    const gate = map['gate'] || ''  // optional in case you haven’t added yet
    const expStr = map['exp'] || '' // optional in case you haven’t added yet

    // ---- Validation paths ----
    // Path A (recommended): gate signature present -> verify with JWT_SECRET
    if (gate && jti && siteId && expStr) {
      const expAt = Number(expStr)
      if (!Number.isFinite(expAt) || Date.now() > expAt) {
        console.warn('[webhook] expired gate token', { jti, siteId, expAt })
        return res.status(200).json({ ok: true, status: 'expired_gate' })
      }

      const meta = `${jti}.${siteId}.${expAt}`
      const sigCheck = await signMeta(meta, jwtSecret)
      if (sigCheck !== gate) {
        console.warn('[webhook] bad gate signature', { jti, siteId })
        return res.status(200).json({ ok: true, status: 'bad_gate_signature' })
      }

      // (Optional) You can also enforce one-time here if you track jti usage in a shared KV.
      // For now we accept since gate is valid & not expired.
      console.log('[webhook] ACCEPT via gate', {
        formId: decrypted.formId,
        submissionId: decrypted.submissionId,
        jti,
        siteId
      })
      return res.status(200).json({ ok: true, status: 'accepted_gate' })
    }

    // Path B (legacy/best-effort): fall back to in-memory pass check (may fail cross-instance)
    if (jti && siteId) {
      const pass = memory.passes.get(jti)
      if (!pass || pass.used || pass.site_id !== siteId) {
        console.warn('[webhook] invalid or missing pass in memory (recommend gate or KV)', { jti, siteId })
        return res.status(200).json({ ok: true, status: 'invalid_token_memory' })
      }
      // mark used one-time (best effort)
      pass.used = true
      memory.passes.set(jti, pass)
      console.log('[webhook] ACCEPT via memory', {
        formId: decrypted.formId,
        submissionId: decrypted.submissionId,
        jti,
        siteId
      })
      return res.status(200).json({ ok: true, status: 'accepted_memory' })
    }

    // Nothing to validate with
    console.warn('[webhook] missing required hidden fields (jti/site_id and/or gate/exp)')
    return res.status(200).json({ ok: true, status: 'missing_hidden_fields' })

  } catch (err) {
    console.error('[webhook] fatal error:', err)
    // Acknowledge 200 so FormSG doesn’t retry forever on malformed/spoofed calls
    return res.status(200).json({ ok: true, status: 'internal_error' })
  }
}

// In-memory fallback (demo)
const memory = globalThis.__NHGP_MEM__ || (
  globalThis.__NHGP_MEM__ = { sessions: new Map(), passes: new Map() }
)

export const config = {
  api: { bodyParser: { sizeLimit: '2mb' } }
}
