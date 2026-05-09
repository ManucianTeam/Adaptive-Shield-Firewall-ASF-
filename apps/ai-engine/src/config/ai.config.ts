// apps/ai-engine/src/config/ai.config.ts

export default () => ({
  ai: {
    // =========================
    // SERVER
    // =========================

    port: parseInt(
      process.env.PORT || '4000',
      10,
    ),

    env:
      process.env.NODE_ENV ||
      'development',

    // =========================
    // DATABASE
    // =========================

    mongoUri:
      process.env.MONGO_URI ||
      'mongodb://localhost:27017/ai-engine',

    // =========================
    // AI THRESHOLDS
    // =========================

    thresholds: {
      warning: parseInt(
        process.env.AI_WARNING_THRESHOLD ||
          '30',
        10,
      ),

      danger: parseInt(
        process.env.AI_DANGER_THRESHOLD ||
          '60',
        10,
      ),

      critical: parseInt(
        process.env.AI_CRITICAL_THRESHOLD ||
          '80',
        10,
      ),

      autoBlock: parseInt(
        process.env.AI_AUTO_BLOCK ||
          '75',
        10,
      ),
    },

    // =========================
    // RATE LIMITS
    // =========================

    rateLimit: {
      requestLimit: parseInt(
        process.env.AI_REQUEST_LIMIT ||
          '1000',
        10,
      ),

      failedRequestLimit: parseInt(
        process.env
          .AI_FAILED_REQUEST_LIMIT ||
          '100',
        10,
      ),

      raceConditionLimit: parseInt(
        process.env
          .AI_RACE_LIMIT || '10',
        10,
      ),
    },

    // =========================
    // BOT DETECTION
    // =========================

    botDetection: {
      confidenceThreshold: parseInt(
        process.env
          .AI_BOT_CONFIDENCE ||
          '60',
        10,
      ),

      suspiciousUserAgentLength:
        parseInt(
          process.env
            .AI_UA_MIN_LENGTH ||
            '10',
          10,
        ),
    },

    // =========================
    // LOGGING
    // =========================

    logging: {
      enabled:
        process.env.AI_LOGGING !==
        'false',

      level:
        process.env.LOG_LEVEL ||
        'debug',
    },
  },
});