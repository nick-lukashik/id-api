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
import { CodeDelivery, type CodeMessage } from '../src/login/code-delivery.js'

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

const signingKey = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
})
    .privateKey.export({
        type: 'pkcs8',
        format: 'pem',
    })
    .toString()
export const INTERNAL_TOKEN = randomBytes(32).toString('hex')

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
        ...overrides,
    })
    env.reset()

    const { AppModule } = await import('../src/app.module.js')
    const delivery = new RecordingDelivery()
    const moduleRef = await Test.createTestingModule({
        imports: [
            AppModule,
        ],
    })
        .overrideProvider(CodeDelivery)
        .useValue(delivery)
        .compile()
    const app = moduleRef.createNestApplication<NestExpressApplication>({
        bufferLogs: true,
    })
    app.useLogger(app.get(Logger))
    configureApp(app)
    await app.init()

    const db = app.get<Db>(DB)
    const redis = app.get<RedisClient>(REDIS)
    await db.execute(sql`truncate users, login_challenges, sessions, role_bindings, outbox, inbox cascade`)
    await redis.flushDb()
    await app.listen(0, '127.0.0.1')
    const { registry } = app.get(Metrics)

    return {
        app,
        db,
        redis,
        delivery,
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
