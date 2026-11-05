import { generateKeyPairSync, randomBytes } from 'node:crypto'
import type { NestExpressApplication } from '@nestjs/platform-express'
import { Test } from '@nestjs/testing'
import { sql } from 'drizzle-orm'
import { Logger } from 'nestjs-pino'
import request from 'supertest'
import { inject } from 'vitest'
import { configureApp } from '../src/app.setup.js'
import { DB } from '../src/common/database/database.js'
import { Metrics } from '../src/common/metrics/metrics.js'
import { REDIS, type RedisClient } from '../src/common/redis/redis.client.js'
import { env } from '../src/config/env.js'
import type { Db } from '../src/db/types.js'
import {
    type GoogleCode,
    type GoogleProfile,
    GoogleProvider,
    GoogleRejected,
    googleHostsEmail,
} from '../src/identities/google.provider.js'
import { CodeDelivery, type CodeMessage } from '../src/login/code-delivery.js'
import { TEST_ORIGIN, TEST_RP_ID } from './authenticator.js'

/** Sign-in codes "sent" during a test, newest last. */
export class RecordingDelivery extends CodeDelivery {
    readonly sent: CodeMessage[] = []
    status: 'accepted' | 'failed' = 'accepted'

    async deliver(message: CodeMessage) {
        this.sent.push(message)
        return this.status
    }

    last() {
        const message = this.sent.at(-1)
        if (!message) throw new Error('no code was sent')
        return message
    }
}

/**
 * Google for tests: a code is `code-<sub>` and stands for the profile set
 * with `account`; the nonce has to be the one of `account` too.
 */
export class FakeGoogle extends GoogleProvider {
    readonly enabled = true
    readonly authorizationEndpoint = 'https://accounts.google.test/o/oauth2/v2/auth'
    readonly clientId = 'test-client.apps.googleusercontent.com'
    readonly redirectUri = 'http://localhost:3100/login/google/callback'
    private readonly accounts = new Map<
        string,
        GoogleProfile & {
            nonce: string
        }
    >()

    account(
        profile: Omit<GoogleProfile, 'hostedByGoogle'> & {
            hd?: string
        },
        nonce = 'n'.repeat(24),
    ) {
        this.accounts.set(profile.subject, {
            ...profile,
            hostedByGoogle: googleHostsEmail(profile.email, profile.hd),
            nonce,
        })
        return {
            code: `code-${profile.subject}`,
            codeVerifier: 'v'.repeat(43),
            nonce,
        }
    }

    async verify({ code, nonce }: GoogleCode): Promise<GoogleProfile> {
        const account = this.accounts.get(code.replace(/^code-/, ''))
        if (!account || account.nonce !== nonce) throw new GoogleRejected('invalid_grant')
        return {
            subject: account.subject,
            email: account.email,
            emailVerified: account.emailVerified,
            hostedByGoogle: account.hostedByGoogle,
            name: account.name,
        }
    }
}

const signingKey = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
})
    .privateKey.export({
        type: 'pkcs8',
        format: 'pem',
    })
    .toString()
export const INTERNAL_TOKEN = randomBytes(32).toString('hex')

/** The redirect URI of the test app (`landing-web`). */
export const SITE_CALLBACK = 'https://site.example.test/auth/callback'

export type TestApp = Awaited<ReturnType<typeof startApp>>

/**
 * The real AppModule against the shared containers, listening on a random
 * port. Every file starts from empty tables and an empty Redis.
 */
export async function startApp(overrides: Record<string, string> = {}) {
    Object.assign(process.env, {
        NODE_ENV: 'test',
        LOG_LEVEL: process.env.TEST_LOG_LEVEL ?? 'silent',
        APP_VERSION: 'test',
        METRICS_PORT: '0',
        DATABASE_URL: inject('databaseUrl'),
        REDIS_URL: inject('redisUrl'),
        RABBITMQ_URL: inject('rabbitmqUrl'),
        TRUST_PROXY_HOPS: '1',
        TOKEN_ISSUER: 'https://id.example.test',
        SIGNING_KEY_PEM: signingKey,
        LOGIN_CODE_PEPPER: randomBytes(32).toString('hex'),
        LOGIN_RESEND_COOLDOWN_MS: '0',
        NOTIFICATIONS_INTERNAL_TOKEN: randomBytes(32).toString('hex'),
        INTERNAL_API_TOKEN: INTERNAL_TOKEN,
        WEBAUTHN_RP_ID: TEST_RP_ID,
        WEBAUTHN_ORIGIN: TEST_ORIGIN,
        OAUTH_CLIENTS: `landing-web=${SITE_CALLBACK}`,
        ...overrides,
    })
    env.reset()

    const { AppModule } = await import('../src/app.module.js')
    const delivery = new RecordingDelivery()
    const google = new FakeGoogle()
    const moduleRef = await Test.createTestingModule({
        imports: [
            AppModule,
        ],
    })
        .overrideProvider(CodeDelivery)
        .useValue(delivery)
        .overrideProvider(GoogleProvider)
        .useValue(google)
        .compile()
    const app = moduleRef.createNestApplication<NestExpressApplication>({
        bufferLogs: true,
    })
    app.useLogger(app.get(Logger))
    configureApp(app)
    await app.init()

    const db = app.get<Db>(DB)
    const redis = app.get<RedisClient>(REDIS)
    await db.execute(
        sql`truncate users, login_challenges, sessions, role_bindings, grants, identities, passkeys, authorization_codes, outbox, inbox cascade`,
    )
    await redis.flushDb()
    await app.listen(0, '127.0.0.1')
    const { registry } = app.get(Metrics)

    return {
        app,
        db,
        redis,
        delivery,
        google,
        url: await app.getUrl(),
        http: () => request(app.getHttpServer()),
        /** Sum of a metric's series that carry `labels` (0 when none). */
        metric: async (name: string, labels: Record<string, string> = {}) => {
            const metric = registry.getSingleMetric(name)
            if (!metric) throw new Error(`no metric ${name}`)
            const { values } = await metric.get()
            return values
                .filter(value => Object.entries(labels).every(([key, label]) => value.labels[key] === label))
                .reduce((sum, value) => sum + value.value, 0)
        },
        close: () => app.close(),
    }
}
