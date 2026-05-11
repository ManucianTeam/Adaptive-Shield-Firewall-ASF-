import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';

import * as request from 'supertest';

import { AppModule } from '../src/app.module';

describe('ASF Auth Service (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture: TestingModule =
      await Test.createTestingModule({
        imports: [AppModule],
      }).compile();

    app = moduleFixture.createNestApplication();

    app.setGlobalPrefix('api');

    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        transform: true,
        forbidNonWhitelisted: true,
      }),
    );

    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  // ==========================================================================
  // Health
  // ==========================================================================

  describe('Health Check', () => {
    it('/GET health', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/health')
        .expect(200);

      expect(response.body.success).toBe(true);
    });
  });

  // ==========================================================================
  // Authentication
  // ==========================================================================

  describe('Authentication Flow', () => {
    const user = {
      email: 'test@asf.local',
      password: 'SecurePassword123!',
      username: 'asf_test_user',
    };

    let accessToken: string;
    let refreshToken: string;

    // ------------------------------------------------------------------------
    // Register
    // ------------------------------------------------------------------------

    it('/POST auth/register', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/auth/register')
        .send(user)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('id');
      expect(response.body.data.email).toBe(user.email);
    });

    // ------------------------------------------------------------------------
    // Login
    // ------------------------------------------------------------------------

    it('/POST auth/login', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/auth/login')
        .send({
          email: user.email,
          password: user.password,
        })
        .expect(200);

      expect(response.body.success).toBe(true);

      expect(response.body.data).toHaveProperty(
        'accessToken',
      );

      expect(response.body.data).toHaveProperty(
        'refreshToken',
      );

      accessToken =
        response.body.data.accessToken;

      refreshToken =
        response.body.data.refreshToken;
    });

    // ------------------------------------------------------------------------
    // Current User
    // ------------------------------------------------------------------------

    it('/GET users/me', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/users/me')
        .set(
          'Authorization',
          `Bearer ${accessToken}`,
        )
        .expect(200);

      expect(response.body.success).toBe(true);

      expect(response.body.data.email).toBe(
        user.email,
      );
    });

    // ------------------------------------------------------------------------
    // Refresh Token
    // ------------------------------------------------------------------------

    it('/POST auth/refresh', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/auth/refresh')
        .send({
          refreshToken,
        })
        .expect(200);

      expect(response.body.success).toBe(true);

      expect(response.body.data).toHaveProperty(
        'accessToken',
      );
    });

    // ------------------------------------------------------------------------
    // Unauthorized Access
    // ------------------------------------------------------------------------

    it('/GET users/me without token', async () => {
      await request(app.getHttpServer())
        .get('/api/users/me')
        .expect(401);
    });

    // ------------------------------------------------------------------------
    // Invalid Credentials
    // ------------------------------------------------------------------------

    it('/POST auth/login invalid credentials', async () => {
      await request(app.getHttpServer())
        .post('/api/auth/login')
        .send({
          email: user.email,
          password: 'invalid-password',
        })
        .expect(401);
    });

    // ------------------------------------------------------------------------
    // Logout
    // ------------------------------------------------------------------------

    it('/POST auth/logout', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/auth/logout')
        .set(
          'Authorization',
          `Bearer ${accessToken}`,
        )
        .send({
          refreshToken,
        })
        .expect(200);

      expect(response.body.success).toBe(true);
    });
  });

  // ==========================================================================
  // Security Validation
  // ==========================================================================

  describe('Security Validation', () => {
    it('should reject malformed JWT', async () => {
      await request(app.getHttpServer())
        .get('/api/users/me')
        .set(
          'Authorization',
          'Bearer malformed.token.value',
        )
        .expect(401);
    });

    it('should reject invalid payload structure', async () => {
      await request(app.getHttpServer())
        .post('/api/auth/register')
        .send({
          invalid: true,
        })
        .expect(400);
    });

    it('should block empty login request', async () => {
      await request(app.getHttpServer())
        .post('/api/auth/login')
        .send({})
        .expect(400);
    });
  });
});