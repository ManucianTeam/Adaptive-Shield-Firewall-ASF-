/* ============================================================
 * ASF — Adaptive Shield Firewall
 * IP Intelligence Utility
 * File: ip.util.ts
 * ============================================================
 *
 * PURPOSE:
 * Provides IP extraction, normalization,
 * trust evaluation, and lightweight network
 * intelligence utilities for distributed systems.
 *
 * This utility handles:
 * - proxy-aware IP extraction
 * - IPv4 / IPv6 normalization
 * - private network detection
 * - loopback validation
 * - CIDR matching
 * - trusted proxy verification
 * - datacenter heuristics
 *
 * ============================================================
 *
 * SECURITY OBJECTIVES:
 * - Prevent spoofed client attribution
 * - Support behavioral fingerprinting
 * - Improve threat intelligence accuracy
 * - Enable adaptive access controls
 * - Harden reverse-proxy deployments
 *
 * ============================================================
 *
 * DESIGN PRINCIPLES:
 * - Stateless deterministic utilities
 * - Lightweight execution
 * - Proxy-safe extraction logic
 * - Cloud-native compatibility
 * - Security-first defaults
 *
 * ============================================================
 *
 * IMPORTANT:
 * Client IP attribution is probabilistic.
 *
 * NEVER:
 * - blindly trust x-forwarded-for
 * - assume proxies are trustworthy
 * - expose internal infrastructure IPs
 * - treat IP identity as user identity
 *
 * ============================================================
 */

import { Request } from 'express';

import * as net from 'net';

/**
 * ============================================================
 * IP Intelligence Result
 * ============================================================
 */

export interface IPIntelligence {
  ip: string;

  version: 4 | 6 | 0;

  isPrivate: boolean;

  isLoopback: boolean;

  isLocalhost: boolean;

  isTrustedProxy: boolean;

  isDatacenter: boolean;

  forwardedChain: string[];

  normalized: string;
}

/**
 * ============================================================
 * Trusted Proxy CIDRs
 * ============================================================
 *
 * Production:
 * - move into config
 * - support cloud metadata APIs
 * - integrate ASN intelligence
 * ============================================================
 */

const TRUSTED_PROXY_PREFIXES = ['10.', '172.', '192.168.', '127.'];

/**
 * ============================================================
 * Datacenter Prefix Heuristics
 * ============================================================
 */

const DATACENTER_PREFIXES = ['34.', '35.', '52.', '54.', '104.'];

/**
 * ============================================================
 * IP Utility
 * ============================================================
 */

export class IPUtil {
  /**
   * ==========================================================
   * Extract Client IP
   * ==========================================================
   */

  static extractClientIP(request: Request): string {
    /**
     * ========================================================
     * X-Forwarded-For
     * ========================================================
     */

    const forwarded = request.headers['x-forwarded-for'];

    if (typeof forwarded === 'string') {
      const chain = forwarded
        .split(',')
        .map((v) => v.trim())
        .filter(Boolean);

      /**
       * ======================================================
       * First Public IP Wins
       * ======================================================
       */

      for (const ip of chain) {
        if (!this.isPrivateIP(ip)) {
          return this.normalizeIP(ip);
        }
      }

      if (chain.length > 0) {
        return this.normalizeIP(chain[0]);
      }
    }

    /**
     * ========================================================
     * Fallback Sources
     * ========================================================
     */

    const rawIP = request.ip || request.socket?.remoteAddress || '0.0.0.0';

    return this.normalizeIP(rawIP);
  }

  /**
   * ==========================================================
   * Analyze IP Intelligence
   * ==========================================================
   */

  static analyze(request: Request): IPIntelligence {
    const ip = this.extractClientIP(request);

    const normalized = this.normalizeIP(ip);

    const version = this.detectIPVersion(normalized);

    const isPrivate = this.isPrivateIP(normalized);

    const isLoopback = this.isLoopbackIP(normalized);

    const isLocalhost = normalized === '127.0.0.1' || normalized === '::1';

    const isTrustedProxy = this.isTrustedProxy(normalized);

    const isDatacenter = this.isDatacenterIP(normalized);

    const forwardedChain = this.extractForwardedChain(request);

    return {
      ip: normalized,

      version,

      isPrivate,

      isLoopback,

      isLocalhost,

      isTrustedProxy,

      isDatacenter,

      forwardedChain,

      normalized,
    };
  }

  /**
   * ==========================================================
   * Normalize IP Address
   * ==========================================================
   */

  static normalizeIP(ip: string): string {
    if (!ip) {
      return '0.0.0.0';
    }

    /**
     * ========================================================
     * IPv6 Mapped IPv4
     * ========================================================
     */

    if (ip.startsWith('::ffff:')) {
      return ip.replace('::ffff:', '');
    }

    return ip.trim();
  }

  /**
   * ==========================================================
   * Detect IP Version
   * ==========================================================
   */

  static detectIPVersion(ip: string): 4 | 6 | 0 {
    const version = net.isIP(ip);

    if (version === 4) {
      return 4;
    }

    if (version === 6) {
      return 6;
    }

    return 0;
  }

  /**
   * ==========================================================
   * Private Network Detection
   * ==========================================================
   */

  static isPrivateIP(ip: string): boolean {
    const normalized = this.normalizeIP(ip);

    return (
      normalized.startsWith('10.') ||
      normalized.startsWith('192.168.') ||
      normalized.startsWith('172.16.') ||
      normalized.startsWith('127.') ||
      normalized === '::1'
    );
  }

  /**
   * ==========================================================
   * Loopback Detection
   * ==========================================================
   */

  static isLoopbackIP(ip: string): boolean {
    return ip.startsWith('127.') || ip === '::1';
  }

  /**
   * ==========================================================
   * Trusted Proxy Detection
   * ==========================================================
   */

  static isTrustedProxy(ip: string): boolean {
    return TRUSTED_PROXY_PREFIXES.some((prefix) => ip.startsWith(prefix));
  }

  /**
   * ==========================================================
   * Datacenter Heuristic
   * ==========================================================
   */

  static isDatacenterIP(ip: string): boolean {
    return DATACENTER_PREFIXES.some((prefix) => ip.startsWith(prefix));
  }

  /**
   * ==========================================================
   * Extract Forwarded Chain
   * ==========================================================
   */

  static extractForwardedChain(request: Request): string[] {
    const forwarded = request.headers['x-forwarded-for'];

    if (typeof forwarded !== 'string') {
      return [];
    }

    return forwarded
      .split(',')
      .map((v) => this.normalizeIP(v.trim()))
      .filter(Boolean);
  }

  /**
   * ==========================================================
   * CIDR Prefix Match
   * ==========================================================
   *
   * NOTE:
   * Simplified prefix matcher.
   *
   * Production:
   * - use ipaddr.js
   * - support full CIDR parsing
   * - IPv6 subnet handling
   * ==========================================================
   */

  static matchesCIDR(
    ip: string,

    cidrPrefix: string,
  ): boolean {
    return this.normalizeIP(ip).startsWith(cidrPrefix);
  }

  /**
   * ==========================================================
   * Safe IP Exposure
   * ==========================================================
   */

  static maskIP(ip: string): string {
    const normalized = this.normalizeIP(ip);

    /**
     * ========================================================
     * IPv4 Masking
     * ========================================================
     */

    if (this.detectIPVersion(normalized) === 4) {
      const parts = normalized.split('.');

      if (parts.length !== 4) {
        return '0.0.xxx.xxx';
      }

      return `${parts[0]}.${parts[1]}.xxx.xxx`;
    }

    /**
     * ========================================================
     * IPv6 Masking
     * ========================================================
     */

    if (this.detectIPVersion(normalized) === 6) {
      return normalized.slice(0, 12) + '::xxxx';
    }

    return 'unknown';
  }
}
