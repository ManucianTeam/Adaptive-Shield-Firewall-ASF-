import { Controller, Get, HttpCode, HttpStatus } from '@nestjs/common';

import { HealthService } from './health.service';

/**
 * ============================================================
 * ASF — Adaptive Shield Firewall
 * System Health & Observability Controller
 * ============================================================
 *
 * RESPONSIBILITY:
 * This controller exposes operational health metrics
 * and infrastructure diagnostics for the ASF ecosystem.
 *
 * CORE OBJECTIVES:
 * - Runtime health validation
 * - Infrastructure dependency monitoring
 * - Service readiness verification
 * - Security pipeline observability
 * - Low-latency health probing
 *
 * IMPORTANT:
 * This controller MUST remain lightweight.
 * No heavy computations should occur here.
 *
 * Designed for:
 * - Kubernetes readiness/liveness probes
 * - Reverse proxy monitoring
 * - Prometheus scraping
 * - Security observability dashboards
 * - Distributed infrastructure diagnostics
 * ============================================================
 */

@Controller('health')
export class HealthController {
  constructor(private readonly healthService: HealthService) {}

  // ============================================================
  // BASIC HEALTH CHECK
  // ============================================================

  /**
   * Lightweight liveness probe.
   *
   * PURPOSE:
   * Confirms that the application process
   * is responsive and operational.
   *
   * SHOULD:
   * - remain extremely fast
   * - avoid external dependencies
   * - avoid database calls
   *
   * TARGET LATENCY:
   * < 1ms ideal response time
   */
  @Get()
  @HttpCode(HttpStatus.OK)
  async healthCheck() {
    return {
      status: 'healthy',
      service: 'adaptive-shield-firewall',
      timestamp: Date.now(),
    };
  }

  // ============================================================
  // READINESS CHECK
  // ============================================================

  /**
   * Infrastructure readiness probe.
   *
   * PURPOSE:
   * Validates that critical dependencies
   * required for traffic processing
   * are operational.
   *
   * CHECKS:
   * - Redis connectivity
   * - Database availability
   * - Internal cache layer
   * - Risk engine readiness
   *
   * USED BY:
   * - Kubernetes readinessProbe
   * - Load balancer routing logic
   */
  @Get('ready')
  @HttpCode(HttpStatus.OK)
  async readinessCheck() {
    return this.healthService.readinessCheck();
  }

  // ============================================================
  // DETAILED SYSTEM METRICS
  // ============================================================

  /**
   * Returns infrastructure telemetry
   * and runtime operational metrics.
   *
   * METRICS:
   * - Event loop delay
   * - Memory consumption
   * - CPU utilization
   * - Redis latency
   * - Database latency
   * - Request throughput
   * - Gateway processing latency
   *
   * IMPORTANT:
   * Protect this endpoint in production.
   */
  @Get('metrics')
  @HttpCode(HttpStatus.OK)
  async metrics() {
    return this.healthService.getSystemMetrics();
  }

  // ============================================================
  // DEPENDENCY HEALTH STATUS
  // ============================================================

  /**
   * Validates external dependency integrity.
   *
   * DEPENDENCIES:
   * - PostgreSQL
   * - Redis Cluster
   * - Internal event bus
   * - Threat intelligence service
   * - Fingerprint processing engine
   */
  @Get('dependencies')
  @HttpCode(HttpStatus.OK)
  async dependencies() {
    return this.healthService.getDependencyHealth();
  }

  // ============================================================
  // SECURITY PIPELINE STATUS
  // ============================================================

  /**
   * Returns status of core ASF
   * security subsystems.
   *
   * COMPONENTS:
   * - Risk scoring engine
   * - Behavioral fingerprint layer
   * - Concurrency protection layer
   * - Threat intelligence pipeline
   * - Adaptive policy engine
   */
  @Get('security')
  @HttpCode(HttpStatus.OK)
  async securityPipelineHealth() {
    return this.healthService.getSecurityPipelineHealth();
  }

  // ============================================================
  // PERFORMANCE DIAGNOSTICS
  // ============================================================

  /**
   * Exposes runtime performance diagnostics.
   *
   * USED FOR:
   * - Latency investigation
   * - Bottleneck detection
   * - Event-loop monitoring
   * - Performance regression analysis
   *
   * IMPORTANT:
   * Keep sampling lightweight
   * to avoid self-induced latency.
   */
  @Get('performance')
  @HttpCode(HttpStatus.OK)
  async performanceDiagnostics() {
    return this.healthService.getPerformanceDiagnostics();
  }
}
