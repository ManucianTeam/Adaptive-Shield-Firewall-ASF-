// apps/auth-service/src/config/security.config.ts

import { registerAs } from '@nestjs/config';

/**
 * ============================================================================
 * ASF Security Configuration
 * ============================================================================
 *
 * Enterprise-grade security configuration layer engineered for adaptive
 * Zero Trust infrastructures, AI-assisted authentication systems, and
 * distributed threat-intelligence environments.
 *
 * Core Responsibilities:
 *
 *  - adaptive security policy orchestration
 *  - behavioral risk-governance configuration
 *  - distributed trust calibration
 *  - brute-force mitigation tuning
 *  - anomaly-detection thresholds
 *  - session hardening policies
 *
 * Security Architecture:
 *
 *  - Zero Trust enforcement model
 *  - defense-in-depth configuration layers
 *  - deterministic access governance
 *  - AI-assisted anomaly correlation
 *  - distributed telemetry integration
 *  - adaptive threat-response orchestration
 *
 * Designed For:
 *
 *  - enterprise IAM infrastructures
 *  - distributed API gateways
 *  - adaptive access-control platforms
 *  - AI-driven authentication ecosystems
 *  - high-concurrency microservice fabrics
 *
 * Integrated Domains:
 *
 *  - behavioral analysis
 *  - geo-intelligence
 *  - request fingerprinting
 *  - session anomaly detection
 *  - brute-force resistance
 *  - threat correlation pipelines
 *
 * ============================================================================
 */

export default registerAs(
  'security',

  () => ({
    /**
     * ------------------------------------------------------------------------
     * Global Security Mode
     * ------------------------------------------------------------------------
     */

    environment:
      process.env.NODE_ENV ||
      'development',

    zeroTrustEnabled:
      process.env.ZERO_TRUST_ENABLED !==
      'false',

    strictMode:
      process.env.SECURITY_STRICT_MODE ===
      'true',

    /**
     * ------------------------------------------------------------------------
     * Adaptive Risk Scoring
     * ------------------------------------------------------------------------
     */

    risk: {
      LOW:
        Number(
          process.env
            .RISK_THRESHOLD_LOW ||
            20,
        ),

      MEDIUM:
        Number(
          process.env
            .RISK_THRESHOLD_MEDIUM ||
            45,
        ),

      HIGH:
        Number(
          process.env
            .RISK_THRESHOLD_HIGH ||
            70,
        ),

      CRITICAL:
        Number(
          process.env
            .RISK_THRESHOLD_CRITICAL ||
            90,
        ),
    },

    /**
     * ------------------------------------------------------------------------
     * Brute-Force Mitigation
     * ------------------------------------------------------------------------
     */

    bruteForce: {
      MAX_LOGIN_ATTEMPTS:
        Number(
          process.env
            .MAX_LOGIN_ATTEMPTS ||
            5,
        ),

      WINDOW_SECONDS:
        Number(
          process.env
            .LOGIN_WINDOW_SECONDS ||
            60,
        ),

      BLOCK_DURATION_SECONDS:
        Number(
          process.env
            .BLOCK_DURATION_SECONDS ||
            900,
        ),

      ENABLE_PROGRESSIVE_DELAY:
        process.env
          .ENABLE_PROGRESSIVE_DELAY !==
        'false',
    },

    /**
     * ------------------------------------------------------------------------
     * Device Fingerprinting
     * ------------------------------------------------------------------------
     */

    fingerprinting: {
      ENABLED:
        process.env
          .FINGERPRINT_ENABLED !==
        'false',

      STRICT_VALIDATION:
        process.env
          .FINGERPRINT_STRICT ===
        'true',

      MAX_DEVICE_VARIATIONS:
        Number(
          process.env
            .MAX_DEVICE_VARIATIONS ||
            5,
        ),

      TRUST_DURATION_DAYS:
        Number(
          process.env
            .DEVICE_TRUST_DAYS ||
            30,
        ),
    },

    /**
     * ------------------------------------------------------------------------
     * Geo-Intelligence Policies
     * ------------------------------------------------------------------------
     */

    geo: {
      ENABLED:
        process.env.GEO_ANALYSIS_ENABLED !==
        'false',

      IMPOSSIBLE_TRAVEL_DISTANCE_KM:
        Number(
          process.env
            .IMPOSSIBLE_TRAVEL_DISTANCE ||
            2000,
        ),

      IMPOSSIBLE_TRAVEL_WINDOW_MIN:
        Number(
          process.env
            .IMPOSSIBLE_TRAVEL_WINDOW ||
            30,
        ),

      HIGH_RISK_COUNTRIES: (
        process.env
          .HIGH_RISK_COUNTRIES ||
        ''
      )
        .split(',')
        .filter(Boolean),
    },

    /**
     * ------------------------------------------------------------------------
     * Behavioral Analysis Engine
     * ------------------------------------------------------------------------
     */

    behavior: {
      ENABLED:
        process.env
          .BEHAVIOR_ANALYSIS_ENABLED !==
        'false',

      MAX_REQUEST_BURST:
        Number(
          process.env
            .MAX_REQUEST_BURST ||
            120,
        ),

      MAX_LOGIN_VELOCITY:
        Number(
          process.env
            .MAX_LOGIN_VELOCITY ||
            10,
        ),

      TIMING_ANOMALY_THRESHOLD:
        Number(
          process.env
            .TIMING_ANOMALY_THRESHOLD ||
            0.85,
        ),
    },

    /**
     * ------------------------------------------------------------------------
     * Session Hardening
     * ------------------------------------------------------------------------
     */

    session: {
      MAX_CONCURRENT_SESSIONS:
        Number(
          process.env
            .MAX_CONCURRENT_SESSIONS ||
            5,
        ),

      REQUIRE_FINGERPRINT:
        process.env
          .SESSION_REQUIRE_FINGERPRINT !==
        'false',

      ENABLE_REFRESH_ROTATION:
        process.env
          .ENABLE_REFRESH_ROTATION !==
        'false',

      FORCE_REAUTH_ON_RISK:
        process.env
          .FORCE_REAUTH_ON_RISK !==
        'false',
    },

    /**
     * ------------------------------------------------------------------------
     * Threat-Response Policies
     * ------------------------------------------------------------------------
     */

    response: {
      AUTO_BLOCK_CRITICAL:
        process.env
          .AUTO_BLOCK_CRITICAL !==
        'false',

      AUTO_REVOKE_SESSION:
        process.env
          .AUTO_REVOKE_SESSION !==
        'false',

      REQUIRE_MFA_ON_HIGH_RISK:
        process.env
          .REQUIRE_MFA_HIGH_RISK !==
        'false',

      ENABLE_SECURITY_ALERTS:
        process.env
          .ENABLE_SECURITY_ALERTS !==
        'false',
    },

    /**
     * ------------------------------------------------------------------------
     * Distributed Telemetry
     * ------------------------------------------------------------------------
     */

    telemetry: {
      ENABLED:
        process.env
          .SECURITY_TELEMETRY_ENABLED !==
        'false',

      STORE_ANOMALY_HISTORY:
        process.env
          .STORE_ANOMALY_HISTORY !==
        'false',

      RETENTION_DAYS:
        Number(
          process.env
            .TELEMETRY_RETENTION_DAYS ||
            30,
        ),
    },
  }),
);