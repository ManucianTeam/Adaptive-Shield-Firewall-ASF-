import {
  Controller,
  Get,
  Post,
  Body,
  Query,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { AdminService } from './admin.service';

/**
 * ASF - Adaptive Shield Firewall
 * Admin Control Plane Controller
 *
 * RESPONSIBILITY:
 * - Security telemetry inspection
 * - Risk score monitoring
 * - Threat event review
 * - System behavior control hooks
 * - Policy tuning interface
 *
 * NOTE:
 * This controller must ONLY expose control-plane operations.
 * No direct data-plane logic should exist here.
 */

@Controller('admin')
export class AdminController {
  constructor(private readonly adminService: AdminService) {}

  // =========================================================
  // SECURITY TELEMETRY
  // =========================================================

  /**
   * Retrieve aggregated system risk metrics
   * Used for real-time dashboard visualization
   */
  @Get('telemetry/risk')
  async getRiskTelemetry(@Query('window') window: string) {
    return this.adminService.getRiskTelemetry(window);
  }

  /**
   * Fetch behavioral anomaly streams
   * Used for security observability layer
   */
  @Get('telemetry/anomalies')
  async getAnomalyStream(@Query('limit') limit: number) {
    return this.adminService.getAnomalyStream(limit || 100);
  }

  // =========================================================
  // THREAT INTELLIGENCE
  // =========================================================

  /**
   * Retrieve detected threats (bot, abuse, injection patterns)
   */
  @Get('threats')
  async getThreats(@Query() query: any) {
    return this.adminService.getThreats(query);
  }

  /**
   * Get detailed analysis of a specific threat event
   */
  @Get('threats/:id')
  async getThreatById(@Param('id') id: string) {
    return this.adminService.getThreatById(id);
  }

  // =========================================================
  // RISK ENGINE CONTROL
  // =========================================================

  /**
   * Override risk threshold dynamically
   * Used for incident response / adaptive tuning
   */
  @Post('risk/threshold')
  @HttpCode(HttpStatus.OK)
  async updateRiskThreshold(@Body() body: { threshold: number }) {
    return this.adminService.updateRiskThreshold(body.threshold);
  }

  /**
   * Force recalibration of scoring model
   */
  @Post('risk/recalibrate')
  @HttpCode(HttpStatus.OK)
  async recalibrateRiskModel() {
    return this.adminService.recalibrateRiskModel();
  }

  // =========================================================
  // POLICY ENGINE CONTROL
  // =========================================================

  /**
   * Update firewall policy rules (behavioral ruleset)
   */
  @Post('policy/update')
  async updatePolicy(@Body() policyDto: any) {
    return this.adminService.updatePolicy(policyDto);
  }

  /**
   * Enable / disable adaptive mode
   */
  @Post('policy/adaptive-mode')
  async setAdaptiveMode(@Body() body: { enabled: boolean }) {
    return this.adminService.setAdaptiveMode(body.enabled);
  }

  // =========================================================
  // SYSTEM HEALTH
  // =========================================================

  /**
   * Retrieve system latency + throughput metrics
   */
  @Get('system/metrics')
  async getSystemMetrics() {
    return this.adminService.getSystemMetrics();
  }

  /**
   * Check internal service health (Redis, fingerprint engine, etc.)
   */
  @Get('system/health')
  async getHealthStatus() {
    return this.adminService.getHealthStatus();
  }

  // =========================================================
  // SECURITY ACTIONS (INCIDENT RESPONSE)
  // =========================================================

  /**
   * Block IP / identity fingerprint instantly
   */
  @Post('action/block')
  async blockIdentity(@Body() body: { ip?: string; fingerprint?: string }) {
    return this.adminService.blockIdentity(body);
  }

  /**
   * Unblock previously blocked entity
   */
  @Post('action/unblock')
  async unblockIdentity(@Body() body: { id: string }) {
    return this.adminService.unblockIdentity(body.id);
  }
}
