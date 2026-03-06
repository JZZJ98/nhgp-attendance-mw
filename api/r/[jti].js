export default async function handler(req, res) {
  try {
    const { jti } = req.query || {}
    if (!jti) return res.status(400).send('Missing token')

    let pass = memory.passes.get(jti)

    // Best-effort memory checks (same-instance)
    if (!pass) {
      // If not found in memory (cross-instance), still allow gate-based flow.
      // We'll construct minimum info from signed cookies if you had them,
      // but for the redirect we only need site_id to prefill.
      const cookies = parseCookie(req.headers.cookie || '')
      const meta = cookies.pass_meta && decodeURIComponent(cookies.pass_meta)
      const sig  = cookies.pass_sig || ''
      if (meta && sig) {
        // optional: could verify here too (we’ll verify again in webhook)
        const parts = meta.split('.')
        if (parts.length === 3 && parts[0] === jti) {
          pass = { site_id: parts[1], expAt: Number(parts[2] || 0) }
        }
      }
    }

    if (!pass) return res.status(410).send('Link expired or invalid')
    if (pass.expAt < Date.now()) return res.status(410).send('Link expired')
    if (pass.redeemed) return res.status(409).send('Already used link')

    // Mark redeemed in memory (best effort)
    pass.redeemed = true
    memory.passes.set(jti, pass)

    // Create short-lived gate token (2 min) for webhook validation
    const expAt = Date.now() + 2 * 60 * 1000
    const meta = `${jti}.${pass.site_id}.${expAt}`
    const secret = process.env.JWT_SECRET || 'devsecret'
    const gate = await signMeta(meta, secret)

    // Redirect to live FormSG with prefilled hidden fields + signed gate
    const formUrl = new URL('https://form.gov.sg/69647c83f2170fd29c8fec32')
    formUrl.searchParams.set('jti', jti)
    formUrl.searchParams.set('site_id', pass.site_id)
    formUrl.searchParams.set('gate', gate)
    formUrl.searchParams.set('exp', String(expAt)) // ms timestamp

    res.writeHead(302, { Location: formUrl.toString() })
    return res.end()
  } catch (e) {
    console.error('[r/[jti]] fatal error:', e)
    return res.status(500).send('Internal error')
  }
}

// ----- Shared helpers -----
async function signMeta(meta, secret) {
  const data = new TextEncoder().encode(secret + '|' + meta)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('')
}

function parseCookie(c){
  const out = {}
  ;(c || '').split(';').forEach((pair) => {
    const idx = pair.indexOf('=')
    if (idx === -1) return
    const k = pair.slice(0, idx).trim()
    const v = pair.slice(idx+1).trim()
    out[k] = v
  })
  return out
}

const memory = globalThis.__NHGP_MEM__ || (
  globalThis.__NHGP_MEM__ = { sessions: new Map(), passes: new Map() }
)
