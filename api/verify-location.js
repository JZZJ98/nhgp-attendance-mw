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
