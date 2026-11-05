import { sql } from 'drizzle-orm'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { startApp, type TestApp } from './harness.js'

describe('how many sign-in codes go out', () => {
    let t: TestApp

    const requestCode = (email: string, ip: string) =>
        t.http().post('/api/v1/login/email').set('x-forwarded-for', ip).send({
            email,
        })
    const challengesOf = async (email: string) =>
        (
            await t.db.execute<{
                n: number
            }>(sql`select count(*)::int as n from login_challenges where email = ${email}`)
        ).rows[0]?.n

    afterAll(async () => {
        await t?.close()
    })

    describe('per IP and from everyone', () => {
        beforeAll(async () => {
            t = await startApp({
                LOGIN_CODES_PER_IP_HOUR: '2',
                LOGIN_CODES_PER_IP_DAY: '100',
                LOGIN_CODES_PER_DAY: '5',
            })
        })

        it('holds one IP to its hourly limit on any number of addresses, and says how long to wait', async () => {
            await requestCode('a1@example.com', '203.0.113.1').expect(202)
            await requestCode('a2@example.com', '203.0.113.1').expect(202)
            const refused = await requestCode('a3@example.com', '203.0.113.1').expect(429)
            expect(refused.body.code).toBe('RATE_LIMITED')
            expect(refused.body.details[0].path).toBe('retryAfterMs')
            expect(await challengesOf('a3@example.com')).toBe(0)
            await requestCode('a3@example.com', '203.0.113.2').expect(202)
        })

        it('stops every code at the shared budget with a 503, and what was refused spent none of it', async () => {
            await requestCode('b1@example.com', '203.0.113.3').expect(202)
            await requestCode('b2@example.com', '203.0.113.3').expect(202)
            const sent = t.delivery.sent.length

            const over = await requestCode('b3@example.com', '203.0.113.4').expect(503)
            expect(over.body.code).toBe('UNAVAILABLE')
            expect(t.delivery.sent).toHaveLength(sent)
            expect(await challengesOf('b3@example.com')).toBe(0)

            const options = await t.http().post('/api/v1/login/passkey/options')
            expect(options.status, JSON.stringify(options.body)).toBeLessThan(300)
        })
    })

    describe('per IP in a day', () => {
        beforeAll(async () => {
            await t?.close()
            t = await startApp({
                LOGIN_CODES_PER_IP_HOUR: '100',
                LOGIN_CODES_PER_IP_DAY: '2',
                LOGIN_CODES_PER_DAY: '100',
            })
        })

        it('holds one IP to its daily limit', async () => {
            await requestCode('c1@example.com', '203.0.113.5').expect(202)
            await requestCode('c2@example.com', '203.0.113.5').expect(202)
            await requestCode('c3@example.com', '203.0.113.5').expect(429)
        })
    })
})
