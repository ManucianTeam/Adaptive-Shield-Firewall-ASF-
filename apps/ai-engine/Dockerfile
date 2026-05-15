# ============================================================
# ASF AI Engine
# Production Docker Runtime
# File: apps/ai-engine/Dockerfile
# ============================================================
#
# PURPOSE:
# Hardened multi-stage production container for the
# ASF AI Engine runtime.
#
# FEATURES:
# - multi-stage optimized build
# - reduced attack surface
# - production-only dependencies
# - non-root execution
# - deterministic runtime
# - smaller final image
# - optimized layer caching
#
# ============================================================
#
# SECURITY OBJECTIVES:
# - minimize container privileges
# - reduce image size & CVE exposure
# - isolate build/runtime layers
# - prevent source leakage
# - harden Node.js execution
#
# ============================================================
#
# IMPORTANT:
# This container is designed for:
# - Kubernetes
# - Docker Swarm
# - ECS/Fargate
# - production orchestration
#
# NEVER:
# - run as root
# - ship devDependencies
# - expose unnecessary ports
# - bake secrets into image
#
# ============================================================

# ============================================================
# STAGE 1 — DEPENDENCIES
# ============================================================

FROM node:20-alpine AS deps

# ============================================================
# Metadata
# ============================================================

LABEL maintainer="ASF Security Team"

# ============================================================
# Runtime Environment
# ============================================================

ENV NODE_ENV=production

# ============================================================
# Work Directory
# ============================================================

WORKDIR /app

# ============================================================
# Install System Dependencies
# ============================================================

RUN apk add --no-cache \
    libc6-compat \
    dumb-init

# ============================================================
# Copy Package Files
# ============================================================

COPY package*.json ./

# ============================================================
# Install Dependencies
# ============================================================
#
# npm ci:
# - deterministic installs
# - faster builds
# - production reliability
#
# ============================================================

RUN npm ci

# ============================================================
# STAGE 2 — BUILD
# ============================================================

FROM node:20-alpine AS builder

# ============================================================
# Environment
# ============================================================

ENV NODE_ENV=development

# ============================================================
# Work Directory
# ============================================================

WORKDIR /app

# ============================================================
# Copy Installed Modules
# ============================================================

COPY --from=deps /app/node_modules ./node_modules

# ============================================================
# Copy Source
# ============================================================

COPY . .

# ============================================================
# Build Application
# ============================================================

RUN npm run build

# ============================================================
# Remove Development Dependencies
# ============================================================

RUN npm prune --omit=dev

# ============================================================
# STAGE 3 — PRODUCTION
# ============================================================

FROM node:20-alpine AS runtime

# ============================================================
# Runtime Metadata
# ============================================================

LABEL app="ASF AI Engine"

LABEL environment="production"

LABEL runtime="nestjs"

# ============================================================
# Runtime Environment
# ============================================================

ENV NODE_ENV=production

ENV PORT=4000

# ============================================================
# Security Hardening
# ============================================================

RUN apk add --no-cache \
    dumb-init

# ============================================================
# Create Non-Root User
# ============================================================

RUN addgroup -S asf && \
    adduser -S asf -G asf

# ============================================================
# Work Directory
# ============================================================

WORKDIR /app

# ============================================================
# Copy Production Artifacts
# ============================================================

COPY --from=builder /app/dist ./dist

COPY --from=builder /app/node_modules ./node_modules

COPY --from=builder /app/package.json ./package.json

# ============================================================
# Ownership
# ============================================================

RUN chown -R asf:asf /app

# ============================================================
# Switch User
# ============================================================

USER asf

# ============================================================
# Expose Runtime Port
# ============================================================

EXPOSE 4000

# ============================================================
# Healthcheck
# ============================================================
#
# IMPORTANT:
# Requires:
# GET /api/health
#
# ============================================================

HEALTHCHECK --interval=30s \
             --timeout=5s \
             --start-period=20s \
             --retries=3 \
CMD node -e "fetch('http://127.0.0.1:4000/api/health').then(() => process.exit(0)).catch(() => process.exit(1))"

# ============================================================
# Runtime Entrypoint
# ============================================================
#
# dumb-init:
# - proper signal forwarding
# - zombie process cleanup
# - graceful shutdown handling
#
# ============================================================

ENTRYPOINT ["dumb-init", "--"]

# ============================================================
# Start Runtime
# ============================================================

CMD ["node", "dist/apps/ai-engine/main.js"]
