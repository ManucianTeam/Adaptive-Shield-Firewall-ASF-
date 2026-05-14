// apps/gateway/src/config/app.config.ts

import { registerAs } from '@nestjs/config';

// ============================================================================
// Gateway Application Configuration
// ============================================================================
//
// Purpose:
//   Centralized runtime configuration for the ASF Gateway service.
//
// Responsibilities:
//   - HTTP runtime configuration
//   - CORS policy management
//   - API prefix management
//   - Rate limiting defaults
//   - Reverse proxy trust configuration
//   - Gateway exposure policies
//
// Security Notes:
//   - All environment variables should be validated externally.
//   - Sensitive secrets should NEVER be hardcoded.
//   - Production deployments should use secret managers.
//
// ============================================================================

export default registerAs(
  'app',

  () => ({
    // ==========================================================================
    // Application Metadata
    // ==========================================================================

    name: process.env.APP_NAME || 'Adaptive Shield Firewall Gateway',

    environment: process.env.NODE_ENV || 'development',

    version: process.env.APP_VERSION || '1.0.0',

    // ==========================================================================
    // HTTP Runtime
    // ==========================================================================

    port: parseInt(process.env.PORT || '3000', 10),

    host: process.env.HOST || '0.0.0.0',

    apiPrefix: process.env.API_PREFIX || 'api',

    // ==========================================================================
    // CORS Configuration
    // ==========================================================================

    cors: {
      enabled: process.env.CORS_ENABLED === 'true',

      origin: process.env.CORS_ORIGIN || '*',

      credentials: process.env.CORS_CREDENTIALS === 'true',

      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],

      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-Requested-With',
        'X-Forwarded-For',
        'X-Device-Fingerprint',
      ],
    },

    // ==========================================================================
    // Trust Proxy
    // ==========================================================================
    //
    // Required when ASF Gateway runs behind:
    //   - NGINX
    //   - Cloudflare
    //   - Kubernetes Ingress
    //   - AWS ALB
    //
    // ==========================================================================

    trustProxy: process.env.TRUST_PROXY === 'true',

    // ==========================================================================
    // Rate Limiting Defaults
    // ==========================================================================

    rateLimit: {
      ttl: parseInt(process.env.RATE_LIMIT_TTL || '60', 10),

      limit: parseInt(process.env.RATE_LIMIT_MAX || '100', 10),
    },

    // ==========================================================================
    // Logging Configuration
    // ==========================================================================

    logging: {
      level: process.env.LOG_LEVEL || 'debug',

      enableRequestLogging: process.env.ENABLE_REQUEST_LOGGING === 'true',
    },

    // ==========================================================================
    // Health Monitoring
    // ==========================================================================

    health: {
      enabled: process.env.HEALTH_CHECK_ENABLED === 'true',

      endpoint: process.env.HEALTH_CHECK_ENDPOINT || '/health',
    },

    // ==========================================================================
    // Gateway Security Headers
    // ==========================================================================

    security: {
      helmetEnabled: process.env.HELMET_ENABLED === 'true',

      compressionEnabled: process.env.COMPRESSION_ENABLED === 'true',
    },
  }),
);
