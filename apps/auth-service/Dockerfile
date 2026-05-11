# ============================================================================
# Adaptive Shield Firewall (ASF) - Auth Service
# Production-Grade Multi-Stage Docker Build
# ============================================================================

# ----------------------------------------------------------------------------
# Stage 1 — Dependencies
# ----------------------------------------------------------------------------
FROM node:22-alpine AS dependencies

WORKDIR /app

# Install system packages
RUN apk add --no-cache libc6-compat

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# ----------------------------------------------------------------------------
# Stage 2 — Build
# ----------------------------------------------------------------------------
FROM node:22-alpine AS builder

WORKDIR /app

# Copy installed node_modules
COPY --from=dependencies /app/node_modules ./node_modules

# Copy source code
COPY . .

# Build NestJS application
RUN npm run build

# Remove development dependencies
RUN npm prune --omit=dev

# ----------------------------------------------------------------------------
# Stage 3 — Production Runtime
# ----------------------------------------------------------------------------
FROM node:22-alpine AS production

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3001

# Security hardening
RUN addgroup -S nestjs && adduser -S nestjs -G nestjs

# Copy runtime dependencies
COPY --from=builder /app/node_modules ./node_modules

# Copy compiled application
COPY --from=builder /app/dist ./dist

# Copy package metadata
COPY --from=builder /app/package*.json ./

# Copy environment files if needed
# COPY .env ./

# Set ownership
RUN chown -R nestjs:nestjs /app

USER nestjs

# Expose auth-service port
EXPOSE 3001

# ----------------------------------------------------------------------------
# Healthcheck
# ----------------------------------------------------------------------------
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:3001/health || exit 1

# ----------------------------------------------------------------------------
# Start Application
# ----------------------------------------------------------------------------
CMD ["node", "dist/main.js"]