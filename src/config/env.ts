import { z } from 'zod'
import {
    baseEnvSchema,
    defineEnv,
    metricsEnvSchema,
    postgresEnvSchema,
    rabbitEnvSchema,
    redisEnvSchema,
} from '../common/config/define-env.js'

const secret = z.string().min(32, 'at least 32 characters')

/** Every variable this service reads. Nothing else touches process.env. */
export const envSchema = baseEnvSchema
    .extend(postgresEnvSchema.shape)
    .extend(redisEnvSchema.shape)
    .extend(rabbitEnvSchema.shape)
    .extend(metricsEnvSchema.shape)
    .extend({
        /** `iss` of access tokens: the public origin of id-web. */
        TOKEN_ISSUER: z.url().default('https://id.nick-lukashik.com'),
        /** `aud` of access tokens; every API of the platform accepts it. */
        TOKEN_AUDIENCE: z.string().min(1).default('nick-lukashik'),
        /** ES256 private key, PKCS#8 PEM (`openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`). */
        SIGNING_KEY_PEM: z.string().includes('BEGIN PRIVATE KEY'),
        /** Public JWKs still accepted during a rotation, JSON array. */
        PREVIOUS_PUBLIC_KEYS: z.string().default('[]'),
        ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(900).default(300),
        REFRESH_TOKEN_TTL_SECONDS: z.coerce.number().int().min(3_600).max(7_776_000).default(2_592_000),
        /** Window in which the previous refresh token gets the token already issued instead of burning the session. */
        REFRESH_GRACE_MS: z.coerce.number().int().min(0).max(60_000).default(20_000),
        /** HMAC key of sign-in codes. */
        LOGIN_CODE_PEPPER: secret,
        LOGIN_CODE_TTL_SECONDS: z.coerce.number().int().min(60).max(3_600).default(600),
        LOGIN_RESEND_COOLDOWN_MS: z.coerce.number().int().min(0).max(600_000).default(60_000),
        LOGIN_MAX_ATTEMPTS: z.coerce.number().int().min(1).max(20).default(5),
        /** notifications-api inside the cluster and its service token (sign-in codes, ADR: synchronous delivery). */
        NOTIFICATIONS_URL: z.url().default('http://notifications-api.prod.svc'),
        NOTIFICATIONS_INTERNAL_TOKEN: secret,
        /** This service's token for in-cluster callers (notifications-api reads users). */
        INTERNAL_API_TOKEN: secret,
    })

export type Env = z.output<typeof envSchema>

export const env = defineEnv(envSchema)
