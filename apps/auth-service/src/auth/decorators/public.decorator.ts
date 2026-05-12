// apps/auth-service/src/auth/decorators/public.decorator.ts

import { SetMetadata } from '@nestjs/common';

/**
 * ============================================================================
 * ASF Public Route Decorator
 * ============================================================================
 *
 * Marks a controller or route handler as publicly accessible,
 * bypassing authentication guards and protected-route enforcement.
 *
 * This decorator is primarily consumed by:
 *
 *  - JwtAuthGuard
 *  - global authentication middleware
 *  - adaptive gateway validation layers
 *  - distributed access-control pipelines
 *
 * Typical Public Endpoints:
 *
 *  - /auth/login
 *  - /auth/register
 *  - /auth/refresh
 *  - /health
 *  - /metrics
 *
 * Security Notes:
 *
 *  - Public routes should remain minimal
 *  - Sensitive operations must never use @Public()
 *  - Public endpoints are still subject to:
 *      - rate limiting
 *      - AI threat analysis
 *      - anomaly detection
 *      - request telemetry
 *
 * ============================================================================
 */

/**
 * --------------------------------------------------------------------------
 * Public Route Metadata Key
 * --------------------------------------------------------------------------
 */

export const IS_PUBLIC_KEY = 'isPublic';

/**
 * --------------------------------------------------------------------------
 * Public Decorator
 * --------------------------------------------------------------------------
 */

export const Public = () =>
  SetMetadata(IS_PUBLIC_KEY, true);