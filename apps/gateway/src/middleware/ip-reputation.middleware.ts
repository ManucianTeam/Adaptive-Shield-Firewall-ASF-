const blockedIps = [
  '1.1.1.1',
];

if (
  blockedIps.includes(req.ip)
) {

  return res.status(403).json({
    success: false,
    reason: 'Bad IP reputation',
  });
}