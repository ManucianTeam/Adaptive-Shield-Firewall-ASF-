// apps/auth-service/src/auth/controllers/auth.controller.ts

import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';

import { Request } from 'express';

import { AuthService } from '../services/auth.service';

import { LoginDto } from '../dto/login.dto';
import { RegisterDto } from '../dto/register.dto';
import { RefreshTokenDto } from '../dto/refresh-token.dto';
import { ForgotPasswordDto } from '../dto/forgot-password.dto';

import { JwtAuthGuard } from '../guards/jwt-auth.guard';

import { Public } from '../decorators/public.decorator';

/**
 * ============================================================================
 * ASF Auth Controller
 * ============================================================================
 *
 * Enterprise-grade authentication orchestration controller responsible for:
 *
 *  - user registration
 *  - credential authentication
 *  - JWT issuance
 *  - refresh token rotation
 *  - session invalidation
 *  - password recovery workflows
 *  - identity verification endpoints
 *
 * Security Characteristics:
 *
 *  - stateless JWT authentication
 *  - adaptive session validation
 *  - AI-assisted threat scoring
 *  - distributed session revocation
 *  - refresh token rotation
 *  - request telemetry support
 *
 * Designed for:
 *
 *  - high-throughput authentication systems
 *  - distributed microservice environments
 *  - Zero Trust architectures
 *  - adaptive security infrastructures
 *
 * ============================================================================
 */

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
  ) {}

  /**
   * --------------------------------------------------------------------------
   * User Registration
   * --------------------------------------------------------------------------
   */

  @Public()
  @Post('register')
  async register(
    @Body() dto: RegisterDto,
    @Req() request: Request,
  ) {
    const result =
      await this.authService.register(
        dto,
        request,
      );

    return {
      success: true,

      message:
        'User registered successfully',

      data: result,
    };
  }

  /**
   * --------------------------------------------------------------------------
   * User Login
   * --------------------------------------------------------------------------
   */

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('login')
  async login(
    @Body() dto: LoginDto,
    @Req() request: Request,
  ) {
    const result =
      await this.authService.login(
        dto,
        request,
      );

    return {
      success: true,

      message:
        'Authentication successful',

      data: result,
    };
  }

  /**
   * --------------------------------------------------------------------------
   * Refresh Access Token
   * --------------------------------------------------------------------------
   */

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('refresh')
  async refresh(
    @Body() dto: RefreshTokenDto,
    @Req() request: Request,
  ) {
    const result =
      await this.authService.refreshToken(
        dto.refreshToken,
        request,
      );

    return {
      success: true,

      message:
        'Token refreshed successfully',

      data: result,
    };
  }

  /**
   * --------------------------------------------------------------------------
   * Logout Session
   * --------------------------------------------------------------------------
   */

  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('logout')
  async logout(
    @Req() request: Request,
    @Body() dto: RefreshTokenDto,
  ) {
    await this.authService.logout(
      request.user,
      dto.refreshToken,
    );

    return {
      success: true,

      message:
        'Session terminated successfully',
    };
  }

  /**
   * --------------------------------------------------------------------------
   * Forgot Password
   * --------------------------------------------------------------------------
   */

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('forgot-password')
  async forgotPassword(
    @Body() dto: ForgotPasswordDto,
  ) {
    await this.authService.forgotPassword(
      dto.email,
    );

    return {
      success: true,

      message:
        'Password recovery workflow initiated',
    };
  }

  /**
   * --------------------------------------------------------------------------
   * Current Session Identity
   * --------------------------------------------------------------------------
   */

  @UseGuards(JwtAuthGuard)
  @Get('me')
  async me(@Req() request: Request) {
    const profile =
      await this.authService.getProfile(
        request.user,
      );

    return {
      success: true,

      data: profile,
    };
  }

  /**
   * --------------------------------------------------------------------------
   * Session Validation
   * --------------------------------------------------------------------------
   */

  @UseGuards(JwtAuthGuard)
  @Get('validate')
  async validate(
    @Req() request: Request,
  ) {
    return {
      success: true,

      authenticated: true,

      user: request.user,
    };
  }

  /**
   * --------------------------------------------------------------------------
   * Health Check
   * --------------------------------------------------------------------------
   */

  @Public()
  @Get('health')
  async health() {
    return {
      success: true,

      service: 'ASF Auth Service',

      status: 'operational',

      timestamp:
        new Date().toISOString(),
    };
  }
}