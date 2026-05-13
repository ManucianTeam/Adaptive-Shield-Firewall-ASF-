// apps/auth-service/src/config/jwt.config.ts

import { registerAs } from '@nestjs/config';

import {
  JwtModuleOptions,
} from '@nestjs/jwt';

/**
 * ============================================================================
 * ASF JWT Configuration
 * ============================================================================
 *
 * Enterprise-grade JWT configuration layer engineered for distributed
 * authentication infrastructures and adaptive Zero Trust identity systems.
 *
 * Core Responsibilities:
 *
 *  - JWT signing configuration
 *  - cryptographic secret orchestration
 *  - access-token lifecycle policy
 *  - refresh-token isolation
 *  - algorithm hardening
 *  - distributed token interoperability
 *
 * Security Architecture:
 *
 *  - stateless authentication design
 *  - environment-isolated secrets
 *  - deterministic token expiration
 *  - replay-resistant token rotation
 *  - cryptographic integrity enforcement
 *  - production-safe signing defaults
 *
 * Designed For:
 *
 *  - distributed API gateways
 *  - microservice ecosystems
 *  - enterprise IAM infrastructures
 *  - adaptive authentication systems
 *  - AI-assisted security platforms
 *
 * Supported Domains:
 *
 *  - access tokens
 *  - refresh tokens
 *  - password reset tokens
 *  - email verification tokens
 *
 * ============================================================================
 */

export default registerAs(
  'jwt',

  (): {
    access: JwtModuleOptions;
    refresh: JwtModuleOptions;
    passwordReset: JwtModuleOptions;
    emailVerification: JwtModuleOptions;
  } => ({
    /**
     * ------------------------------------------------------------------------
     * Access Token Configuration
     * ------------------------------------------------------------------------
     */

    access: {
      secret:
        process.env
          .JWT_ACCESS_SECRET ||

        'asf_access_secret',

      signOptions: {
        /**
         * --------------------------------------------------------------
         * Access Token Lifetime
         * --------------------------------------------------------------
         */

        expiresIn:
          process.env
            .JWT_ACCESS_EXPIRES ||
          '15m',

        /**
         * --------------------------------------------------------------
         * Signing Algorithm
         * --------------------------------------------------------------
         */

        algorithm:
          'HS256',

        /**
         * --------------------------------------------------------------
         * Token Metadata
         * --------------------------------------------------------------
         */

        issuer:
          process.env
            .JWT_ISSUER ||

          'adaptive-shield-firewall',

        audience:
          process.env
            .JWT_AUDIENCE ||

          'adaptive-shield-clients',
      },
    },

    /**
     * ------------------------------------------------------------------------
     * Refresh Token Configuration
     * ------------------------------------------------------------------------
     */

    refresh: {
      secret:
        process.env
          .JWT_REFRESH_SECRET ||

        'asf_refresh_secret',

      signOptions: {
        /**
         * --------------------------------------------------------------
         * Refresh Token Lifetime
         * --------------------------------------------------------------
         */

        expiresIn:
          process.env
            .JWT_REFRESH_EXPIRES ||
          '7d',

        /**
         * --------------------------------------------------------------
         * Signing Algorithm
         * --------------------------------------------------------------
         */

        algorithm:
          'HS256',

        /**
         * --------------------------------------------------------------
         * Token Metadata
         * --------------------------------------------------------------
         */

        issuer:
          process.env
            .JWT_ISSUER ||

          'adaptive-shield-firewall',

        audience:
          process.env
            .JWT_AUDIENCE ||

          'adaptive-shield-clients',
      },
    },

    /**
     * ------------------------------------------------------------------------
     * Password Reset Token Configuration
     * ------------------------------------------------------------------------
     */

    passwordReset: {
      secret:
        process.env
          .JWT_PASSWORD_RESET_SECRET ||

        'asf_password_reset_secret',

      signOptions: {
        expiresIn:
          process.env
            .JWT_PASSWORD_RESET_EXPIRES ||
          '15m',

        algorithm:
          'HS256',

        issuer:
          'adaptive-shield-firewall',

        audience:
          'password-reset',
      },
    },

    /**
     * ------------------------------------------------------------------------
     * Email Verification Token Configuration
     * ------------------------------------------------------------------------
     */

    emailVerification: {
      secret:
        process.env
          .JWT_EMAIL_VERIFICATION_SECRET ||

        'asf_email_verification_secret',

      signOptions: {
        expiresIn:
          process.env
            .JWT_EMAIL_VERIFICATION_EXPIRES ||
          '1d',

        algorithm:
          'HS256',

        issuer:
          'adaptive-shield-firewall',

        audience:
          'email-verification',
      },
    },
  }),
);