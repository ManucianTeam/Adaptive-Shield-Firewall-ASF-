// apps/auth-service/src/ai-security/ai-security.module.ts

import { Global, Module } from '@nestjs/common';

import { AnomalyAnalyzer } from './analyzers/anomaly.analyzer';
import { BehaviorAnalyzer } from './analyzers/behavior.analyzer';
import { GeoAnalyzer } from './analyzers/geo.analyzer';
import { TimingAnalyzer } from './analyzers/timing.analyzer';

import { RiskScoreService } from './services/risk-score.service';

/**
 * ============================================================================
 * ASF AI Security Module
 * ============================================================================
 *
 * Centralized adaptive security intelligence module responsible for:
 *
 *  - behavioral analysis
 *  - anomaly detection
 *  - geospatial threat intelligence
 *  - timing-based automation detection
 *  - adaptive risk aggregation
 *  - distributed security scoring
 *
 * This module acts as the primary orchestration layer for all
 * AI-assisted security analysis pipelines inside the ASF Auth Service.
 *
 * Architecture Goals:
 *
 *  - ultra-low latency execution
 *  - deterministic security scoring
 *  - horizontally scalable analysis
 *  - modular analyzer composition
 *  - distributed authentication hardening
 *  - future ML integration readiness
 *
 * Exported Providers:
 *
 *  - AnomalyAnalyzer
 *  - BehaviorAnalyzer
 *  - GeoAnalyzer
 *  - TimingAnalyzer
 *  - RiskScoreService
 *
 * Future Expansion:
 *
 *  - online learning engines
 *  - sequence transformers
 *  - federated threat intelligence
 *  - graph-based trust systems
 *  - distributed AI inference pipelines
 *
 * ============================================================================
 */

@Global()
@Module({
  providers: [
    // ------------------------------------------------------------------------
    // Core Analyzers
    // ------------------------------------------------------------------------

    AnomalyAnalyzer,

    BehaviorAnalyzer,

    GeoAnalyzer,

    TimingAnalyzer,

    // ------------------------------------------------------------------------
    // Risk Aggregation
    // ------------------------------------------------------------------------

    RiskScoreService,
  ],

  exports: [
    // ------------------------------------------------------------------------
    // Exported Security Intelligence Layer
    // ------------------------------------------------------------------------

    AnomalyAnalyzer,

    BehaviorAnalyzer,

    GeoAnalyzer,

    TimingAnalyzer,

    RiskScoreService,
  ],
})
export class AiSecurityModule {}