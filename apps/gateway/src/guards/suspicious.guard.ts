if (score > 80) {

  throw new ForbiddenException(
    'Suspicious activity',
  );
}