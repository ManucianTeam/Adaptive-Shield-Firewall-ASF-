const lockKey =
`lock:${userId}:${endpoint}`;

const acquired =
await redis.set(
  lockKey,
  '1',
  'PX',
  5000,
  'NX',
);

if (!acquired) {

  return res.status(429).json({
    success: false,
    reason:
    'Duplicate transaction',
  });
}