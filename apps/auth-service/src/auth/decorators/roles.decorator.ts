// apps/auth-service/src/auth/decorators/roles.decorator.ts

import { SetMetadata } from '@nestjs/common';

/**
 * ============================================================================
 * ASF Role-Based Access Control Decorator
 * ============================================================================
 *
 * Declarative RBAC metadata decorator used to enforce
 * role-scoped authorization policies across protected routes.
 *
 * Integrated With:
 *
 *  - RolesGuard
 *  - JwtAuthGuard
 *  - distributed permission gateways
 *  - adaptive authorization pipelines
 *  - Zero Trust access-control layers
 *
 * Supported Security Capabilities:
 *
 *  - hierarchical role validation
 *  - multi-role authorization
 *  - endpoint-level privilege isolation
 *  - distributed identity enforcement
 *  - privilege escalation prevention
 *
 * Example:
 *
 * @Roles('admin')
 *
 * @Roles('admin', 'moderator')
 *
 * ============================================================================
 */

/**
 * --------------------------------------------------------------------------
 * Roles Metadata Key
 * --------------------------------------------------------------------------
 */

export const ROLES_KEY = 'roles';

/**
 * --------------------------------------------------------------------------
 * System Role Definitions
 * --------------------------------------------------------------------------
 */

export type SystemRole =
  | 'super-admin'
  | 'admin'
  | 'moderator'
  | 'security-analyst'
  | 'developer'
  | 'support'
  | 'user'
  | 'guest';

/**
 * --------------------------------------------------------------------------
 * Roles Decorator
 * --------------------------------------------------------------------------
 *
 * Attaches required authorization roles to the route metadata.
 */

export const Roles = (
  ...roles: SystemRole[]
) => SetMetadata(ROLES_KEY, roles);