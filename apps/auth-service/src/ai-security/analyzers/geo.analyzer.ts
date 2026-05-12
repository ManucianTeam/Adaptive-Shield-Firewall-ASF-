import { Injectable, Logger } from '@nestjs/common';

export interface GeoAnalysisInput {
  userId?: string;

  ip: string;

  currentCountry?: string;
  currentCity?: string;

  previousCountry?: string;
  previousCity?: string;

  latitude?: number;
  longitude?: number;

  previousLatitude?: number;
  previousLongitude?: number;

  currentTimestamp: number;
  previousTimestamp?: number;

  vpnDetected?: boolean;
  torDetected?: boolean;
  proxyDetected?: boolean;

  datacenterAsn?: boolean;

  trustedRegion?: boolean;
}

export interface GeoAnalysisResult {
  score: number;

  risk:
    | 'low'
    | 'medium'
    | 'high'
    | 'critical';

  flags: string[];

  impossibleTravel: boolean;

  estimatedVelocityKmh?: number;

  distanceKm?: number;

  metadata: {
    analyzedAt: string;
    geoConfidence: number;
  };
}

/**
 * ============================================================================
 * ASF AI Security — Geo Analyzer
 * ============================================================================
 *
 * Distributed geospatial threat intelligence analyzer designed for
 * authentication risk evaluation and adaptive trust scoring.
 *
 * This analyzer evaluates:
 *
 *  - impossible travel events
 *  - VPN / TOR / proxy infrastructure usage
 *  - datacenter-origin authentication attempts
 *  - geographic trust continuity
 *  - cross-region session anomalies
 *  - velocity-based identity inconsistencies
 *
 * The engine is intentionally lightweight and deterministic to support:
 *
 *  - edge authentication systems
 *  - real-time request pipelines
 *  - low-latency distributed environments
 *  - horizontally scaled microservice architectures
 *
 * Future iterations may integrate:
 *
 *  - ASN reputation intelligence
 *  - geopolitical threat weighting
 *  - adaptive geo trust learning
 *  - federated IP reputation exchange
 *  - sequence-based travel modeling
 *
 * ============================================================================
 */

@Injectable()
export class GeoAnalyzer {
  private readonly logger = new Logger(
    GeoAnalyzer.name,
  );

  /**
   * --------------------------------------------------------------------------
   * Main Geospatial Analysis
   * --------------------------------------------------------------------------
   */

  analyze(
    input: GeoAnalysisInput,
  ): GeoAnalysisResult {
    let score = 0;

    const flags: string[] = [];

    let impossibleTravel = false;

    let estimatedVelocityKmh: number | undefined;

    let distanceKm: number | undefined;

    // ------------------------------------------------------------------------
    // VPN / Proxy / TOR Detection
    // ------------------------------------------------------------------------

    if (input.vpnDetected) {
      score += 15;

      flags.push(
        'vpn_infrastructure_detected',
      );
    }

    if (input.proxyDetected) {
      score += 12;

      flags.push(
        'proxy_network_detected',
      );
    }

    if (input.torDetected) {
      score += 35;

      flags.push(
        'tor_exit_node_detected',
      );
    }

    // ------------------------------------------------------------------------
    // Datacenter Infrastructure Detection
    // ------------------------------------------------------------------------

    if (input.datacenterAsn) {
      score += 20;

      flags.push(
        'datacenter_network_origin',
      );
    }

    // ------------------------------------------------------------------------
    // Trusted Region Validation
    // ------------------------------------------------------------------------

    if (input.trustedRegion === false) {
      score += 10;

      flags.push(
        'untrusted_geographic_region',
      );
    }

    // ------------------------------------------------------------------------
    // Impossible Travel Detection
    // ------------------------------------------------------------------------

    const hasGeoData =
      input.latitude !== undefined &&
      input.longitude !== undefined &&
      input.previousLatitude !== undefined &&
      input.previousLongitude !== undefined &&
      input.previousTimestamp !== undefined;

    if (hasGeoData) {
      distanceKm = this.calculateDistanceKm(
        input.previousLatitude!,
        input.previousLongitude!,
        input.latitude!,
        input.longitude!,
      );

      const elapsedHours =
        (input.currentTimestamp -
          input.previousTimestamp!) /
        1000 /
        60 /
        60;

      if (elapsedHours > 0) {
        estimatedVelocityKmh =
          distanceKm / elapsedHours;

        if (estimatedVelocityKmh > 900) {
          score += 45;

          impossibleTravel = true;

          flags.push(
            'impossible_travel_detected',
          );
        }

        if (estimatedVelocityKmh > 500) {
          score += 20;

          flags.push(
            'abnormal_travel_velocity',
          );
        }
      }
    }

    // ------------------------------------------------------------------------
    // Country Transition Analysis
    // ------------------------------------------------------------------------

    if (
      input.previousCountry &&
      input.currentCountry &&
      input.previousCountry !==
        input.currentCountry
    ) {
      score += 8;

      flags.push(
        'cross_country_authentication_transition',
      );
    }

    // ------------------------------------------------------------------------
    // Score Normalization
    // ------------------------------------------------------------------------

    const normalizedScore = Math.min(
      100,
      Math.max(0, score),
    );

    // ------------------------------------------------------------------------
    // Risk Classification
    // ------------------------------------------------------------------------

    let risk:
      | 'low'
      | 'medium'
      | 'high'
      | 'critical' = 'low';

    if (normalizedScore >= 75) {
      risk = 'critical';
    } else if (normalizedScore >= 45) {
      risk = 'high';
    } else if (normalizedScore >= 20) {
      risk = 'medium';
    }

    // ------------------------------------------------------------------------
    // Security Telemetry
    // ------------------------------------------------------------------------

    this.logger.warn({
      message:
        'Geospatial security analysis completed',

      userId: input.userId,

      ip: input.ip,

      risk,

      score: normalizedScore,

      impossibleTravel,

      estimatedVelocityKmh,

      distanceKm,

      flags,
    });

    return {
      score: normalizedScore,

      risk,

      flags,

      impossibleTravel,

      estimatedVelocityKmh,

      distanceKm,

      metadata: {
        analyzedAt:
          new Date().toISOString(),

        geoConfidence:
          1 - normalizedScore / 100,
      },
    };
  }

  /**
   * --------------------------------------------------------------------------
   * Haversine Distance Formula
   * --------------------------------------------------------------------------
   *
   * Calculates great-circle distance between two geographic coordinates.
   *
   * Earth radius approximation:
   * 6371 km
   *
   * --------------------------------------------------------------------------
   */

  private calculateDistanceKm(
    lat1: number,
    lon1: number,
    lat2: number,
    lon2: number,
  ): number {
    const R = 6371;

    const dLat = this.toRadians(
      lat2 - lat1,
    );

    const dLon = this.toRadians(
      lon2 - lon1,
    );

    const a =
      Math.sin(dLat / 2) *
        Math.sin(dLat / 2) +
      Math.cos(this.toRadians(lat1)) *
        Math.cos(this.toRadians(lat2)) *
        Math.sin(dLon / 2) *
        Math.sin(dLon / 2);

    const c =
      2 *
      Math.atan2(
        Math.sqrt(a),
        Math.sqrt(1 - a),
      );

    return R * c;
  }

  /**
   * --------------------------------------------------------------------------
   * Degree → Radian Conversion
   * --------------------------------------------------------------------------
   */

  private toRadians(value: number): number {
    return (value * Math.PI) / 180;
  }
}