res.setHeader(
  'X-Frame-Options',
  'DENY',
);

res.setHeader(
  'X-Content-Type-Options',
  'nosniff',
);

res.setHeader(
  'Content-Security-Policy',
  "default-src 'self'",
);