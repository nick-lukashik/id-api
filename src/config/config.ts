import { registerAs } from '@nestjs/config'
import { env } from './env.js'

/** Service name: logs, metrics, connection names, Redis key prefix. */
export const SERVICE_NAME = 'id-api'

export const appConfig = registerAs('app', () => ({
    service: SERVICE_NAME,
    nodeEnv: env().NODE_ENV,
    production: env().NODE_ENV === 'production',
    port: env().PORT,
    version: env().APP_VERSION,
    logLevel: env().LOG_LEVEL,
    trustProxyHops: env().TRUST_PROXY_HOPS,
    shutdownDelayMs: env().SHUTDOWN_DELAY_MS,
    metricsPort: env().METRICS_PORT,
}))

export const dbConfig = registerAs('db', () => ({
    url: env().DATABASE_URL,
    max: env().DATABASE_POOL_MAX,
}))

export const redisConfig = registerAs('redis', () => ({
    url: env().REDIS_URL,
}))

export const rabbitConfig = registerAs('rabbit', () => ({
    url: env().RABBITMQ_URL,
}))

export const tokenConfig = registerAs('token', () => ({
    issuer: env().TOKEN_ISSUER,
    audience: env().TOKEN_AUDIENCE,
    privateKeyPem: env().SIGNING_KEY_PEM,
    previousPublicKeys: env().PREVIOUS_PUBLIC_KEYS,
    accessTtlSec: env().ACCESS_TOKEN_TTL_SECONDS,
    refreshTtlSec: env().REFRESH_TOKEN_TTL_SECONDS,
    refreshGraceMs: env().REFRESH_GRACE_MS,
}))

export const loginConfig = registerAs('login', () => ({
    pepper: env().LOGIN_CODE_PEPPER,
    codeTtlSec: env().LOGIN_CODE_TTL_SECONDS,
    resendCooldownMs: env().LOGIN_RESEND_COOLDOWN_MS,
    maxAttempts: env().LOGIN_MAX_ATTEMPTS,
}))

export const internalConfig = registerAs('internal', () => ({
    notificationsUrl: env().NOTIFICATIONS_URL,
    notificationsToken: env().NOTIFICATIONS_INTERNAL_TOKEN,
    token: env().INTERNAL_API_TOKEN,
}))

export const googleConfig = registerAs('google', () => ({
    clientId: env().GOOGLE_CLIENT_ID,
    clientSecret: env().GOOGLE_CLIENT_SECRET,
    redirectUri: env().GOOGLE_REDIRECT_URI,
}))

export const webauthnConfig = registerAs('webauthn', () => ({
    rpId: env().WEBAUTHN_RP_ID,
    rpName: env().WEBAUTHN_RP_NAME,
    origin: env().WEBAUTHN_ORIGIN,
    freshSignInMs: env().PASSKEY_FRESH_SIGN_IN_MS,
    /** A challenge lives this long; the browser ceremony has the same timeout. */
    challengeTtlMs: 300_000,
    maxPerUser: 10,
}))

export const oauthConfig = registerAs('oauth', () => ({
    clients: env().OAUTH_CLIENTS,
    codeTtlMs: 60_000,
}))
