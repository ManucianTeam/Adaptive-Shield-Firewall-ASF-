const suspiciousAgents = [
  'python',
  'curl',
  'wget',
  'selenium',
  'headless',
];

const ua =
(req.headers['user-agent'] || '')
.toLowerCase();

const detected =
suspiciousAgents.some(
x => ua.includes(x),
);

if (detected) {

  return res.status(403).json({
    success: false,
    reason: 'Bot detected',
  });
}