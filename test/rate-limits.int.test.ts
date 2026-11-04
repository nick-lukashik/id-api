import { randomUUID } from 'node:crypto'
import { createClient } from '@redis/client'
import { sql } from 'drizzle-orm'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { startOwnRedis, stopContainer } from './containers.js'
import { startApp, type TestApp } from './harness.js'

/** Redis is filled up and stopped in this file, so it has its own instance. */
describe('sign-in limits without a working Redis', () => {
    let redis: Awaited<ReturnType<typeof startOwnRedis>>
    let t: TestApp

    beforeAll(async () => {
        redis = await startOwnRedis()
        t = await startApp({
            REDIS_URL: redis.url,
        })
    })
    afterAll(async () => {
        await t?.close()
        await redis?.container.stop()
    })

    /** Redis keeps answering PING and reads but refuses every write, as `noeviction` does when memory is full. */
    async function refuseWrites(refuse: boolean) {
        const admin = createClient({
            url: redis.url,
        })
        await admin.connect()
        await admin.configSet('maxmemory', refuse ? '1' : '0')
        admin.destroy()
    }

    const requestCode = (email: string) =>
        t.http().post('/api/v1/login/email').send({
            email,
        })
    const challengesOf = async (email: string) =>
        (
            await t.db.execute<{
                n: number
            }>(sql`select count(*)::int as n from login_challenges where email = ${email}`)
        ).rows[0]?.n

    it('refuses every sign-in with 503 while Redis refuses writes, sends no code and counts each', async () => {
        await refuseWrites(true)
        try {
            const unchecked = await t.metric('rate_limit_fail_open_total')
            const sent = t.delivery.sent.length

            const code = await requestCode('flood@example.com')
            expect(code.status, JSON.stringify(code.body)).toBe(503)
            expect(code.body.code).toBe('UNAVAILABLE')
            expect(t.delivery.sent).toHaveLength(sent)
            expect(await challengesOf('flood@example.com')).toBe(0)

            const verify = await t.http().post('/api/v1/login/email/verify').send({
                challengeId: randomUUID(),
                code: '123456',
            })
            expect(verify.status, JSON.stringify(verify.body)).toBe(503)

            const google = await t
                .http()
                .post('/api/v1/login/google')
                .send({
                    code: 'code-nobody',
                    codeVerifier: 'v'.repeat(43),
                    nonce: 'n'.repeat(24),
                })
            expect(google.status, JSON.stringify(google.body)).toBe(503)

            const options = await t.http().post('/api/v1/login/passkey/options')
            expect(options.status, JSON.stringify(options.body)).toBe(503)

            const passkey = await t
                .http()
                .post('/api/v1/login/passkey/verify')
                .send({
                    challengeId: randomUUID(),
                    response: {
                        id: 'credential',
                        rawId: 'credential',
                        type: 'public-key',
                        response: {
                            clientDataJSON: 'e30',
                        },
                    },
                })
            expect(passkey.status, JSON.stringify(passkey.body)).toBe(503)

            // One per refused request: the alert RateLimitFailingOpen watches this counter.
            expect(await t.metric('rate_limit_fail_open_total')).toBe(unchecked + 5)
        } finally {
            await refuseWrites(false)
        }
        await requestCode('flood@example.com').expect(202)
        expect(t.delivery.last().email).toBe('flood@example.com')
    })

    it('fails readiness while Redis refuses writes, though it still answers PING', async () => {
        await t.http().get('/health/ready').expect(200)
        await refuseWrites(true)
        try {
            const ready = await t.http().get('/health/ready')
            expect(ready.status).toBe(503)
            expect(ready.body.details['rate-limits'].status).toBe('down')
            expect(ready.body.details.redis.status).toBe('up')
        } finally {
            await refuseWrites(false)
        }
        await t.http().get('/health/ready').expect(200)
    })

    it('refuses a code with 503 while Redis is down, and counts it', async () => {
        await stopContainer(redis.container)
        await expect
            .poll(() => t.redis.isReady, {
                timeout: 15_000,
            })
            .toBe(false)
        const unchecked = await t.metric('rate_limit_fail_open_total')
        const sent = t.delivery.sent.length

        const code = await requestCode('outage@example.com')
        expect(code.status, JSON.stringify(code.body)).toBe(503)
        expect(code.body.code).toBe('UNAVAILABLE')
        expect(t.delivery.sent).toHaveLength(sent)
        expect(await challengesOf('outage@example.com')).toBe(0)
        expect(await t.metric('rate_limit_fail_open_total')).toBe(unchecked + 1)
    })
})
