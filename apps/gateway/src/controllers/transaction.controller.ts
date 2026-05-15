import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Req,
  UseGuards,
  Ip,
} from '@nestjs/common';

import { Request } from 'express';

import { TransactionService } from './transaction.service';
import { AuthGuard } from '../auth/guards/auth.guard';

/**
 * ============================================================
 * ASF — Adaptive Shield Firewall
 * Transaction Security Controller
 * ============================================================
 *
 * SECURITY ROLE:
 * Handles high-risk transactional operations under
 * adaptive behavioral security enforcement.
 *
 * CORE OBJECTIVES:
 * - Transaction integrity protection
 * - Replay attack mitigation
 * - Concurrency conflict prevention
 * - Behavioral transaction scoring
 * - Fraud telemetry generation
 * - Session continuity validation
 *
 * IMPORTANT:
 * This controller is part of the
 * critical security-sensitive request path.
 *
 * Heavy operations MUST be delegated
 * to async workers or specialized services.
 *
 * TARGET CHARACTERISTICS:
 * - Low latency
 * - Deterministic validation flow
 * - Idempotent execution model
 * - Distributed-safe transaction orchestration
 * ============================================================
 */

@Controller('transactions')
@UseGuards(AuthGuard)
export class TransactionController {
  constructor(private readonly transactionService: TransactionService) {}

  // ============================================================
  // CREATE TRANSACTION
  // ============================================================

  /**
   * Initiates a protected transactional operation.
   *
   * SECURITY FLOW:
   * 1. Session validation
   * 2. Behavioral context extraction
   * 3. Risk scoring
   * 4. Concurrency validation
   * 5. Idempotency verification
   * 6. Atomic execution
   * 7. Audit logging
   */
  @Post()
  @HttpCode(HttpStatus.CREATED)
  async createTransaction(
    @Body()
    body: {
      amount: number;
      currency: string;
      targetAccount: string;
      idempotencyKey: string;
    },

    @Req() req: Request,

    @Ip() ip: string,
  ) {
    const context = this.buildTransactionContext(req, ip);

    return this.transactionService.createTransaction({
      amount: body.amount,
      currency: body.currency,
      targetAccount: body.targetAccount,
      idempotencyKey: body.idempotencyKey,
      context,
    });
  }

  // ============================================================
  // VALIDATE TRANSACTION
  // ============================================================

  /**
   * Performs pre-execution validation.
   *
   * USED FOR:
   * - Risk pre-check
   * - Fraud analysis
   * - Transaction simulation
   * - Policy enforcement
   */
  @Post('validate')
  @HttpCode(HttpStatus.OK)
  async validateTransaction(
    @Body()
    body: {
      amount: number;
      currency: string;
      targetAccount: string;
    },

    @Req() req: Request,

    @Ip() ip: string,
  ) {
    const context = this.buildTransactionContext(req, ip);

    return this.transactionService.validateTransaction({
      amount: body.amount,
      currency: body.currency,
      targetAccount: body.targetAccount,
      context,
    });
  }

  // ============================================================
  // TRANSACTION STATUS
  // ============================================================

  /**
   * Retrieves transactional execution state.
   *
   * STATES:
   * - pending
   * - processing
   * - completed
   * - rejected
   * - blocked
   * - flagged
   */
  @Get(':id/status')
  @HttpCode(HttpStatus.OK)
  async getTransactionStatus(@Param('id') transactionId: string) {
    return this.transactionService.getTransactionStatus(transactionId);
  }

  // ============================================================
  // TRANSACTION DETAILS
  // ============================================================

  /**
   * Retrieves detailed transaction metadata.
   *
   * SECURITY DATA:
   * - Risk score
   * - Behavioral indicators
   * - Concurrency validation state
   * - Session continuity metadata
   * - Fraud signals
   */
  @Get(':id')
  @HttpCode(HttpStatus.OK)
  async getTransactionById(@Param('id') transactionId: string) {
    return this.transactionService.getTransactionById(transactionId);
  }

  // ============================================================
  // TRANSACTION REVERSAL
  // ============================================================

  /**
   * Initiates secure transaction reversal.
   *
   * SECURITY REQUIREMENTS:
   * - Multi-layer authorization
   * - Replay prevention
   * - Audit integrity enforcement
   * - Behavioral anomaly validation
   */
  @Post(':id/reverse')
  @HttpCode(HttpStatus.OK)
  async reverseTransaction(
    @Param('id') transactionId: string,

    @Req() req: Request,

    @Ip() ip: string,
  ) {
    const context = this.buildTransactionContext(req, ip);

    return this.transactionService.reverseTransaction({
      transactionId,
      context,
    });
  }

  // ============================================================
  // INTERNAL CONTEXT CONSTRUCTION
  // ============================================================

  /**
   * Constructs lightweight behavioral
   * transaction metadata for downstream
   * security engines.
   *
   * DESIGN NOTE:
   * Avoid expensive computations here.
   * This layer exists only for
   * lightweight context extraction.
   */
  private buildTransactionContext(req: Request, ip: string) {
    return {
      ip,

      userAgent: req.headers['user-agent'] || 'unknown',

      requestId: (req.headers['x-request-id'] as string) || null,

      forwardedFor: (req.headers['x-forwarded-for'] as string) || null,

      sessionId: (req.headers['x-session-id'] as string) || null,

      method: req.method,

      path: req.originalUrl,

      timestamp: Date.now(),

      headers: {
        origin: req.headers['origin'],
        referer: req.headers['referer'],
        contentType: req.headers['content-type'],
      },
    };
  }
}
