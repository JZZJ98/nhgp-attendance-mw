export default async function handler(req, res) {
  console.log('[webhooks/_debug] hit:', {
    method: req.method,
    hasSig: !!req.headers['x-formsg-signature'],
    contentType: req.headers['content-type'] || '(none)'
  })
  return res.status(200).json({ ok: true })
}
