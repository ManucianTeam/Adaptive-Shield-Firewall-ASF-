const blockedCountries = [
  'RU',
  'KP',
];

if (
  blockedCountries.includes(
    geo.country,
  )
) {
  return res.status(403).json({
    success: false,
  });
}