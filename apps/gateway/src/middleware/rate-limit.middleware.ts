export const limiter = rateLimit({

  windowMs: 60 * 1000,

  max: 100,

  standardHeaders: true,

  message: {
    success: false,
    error: 'Too many requests',
  },
});