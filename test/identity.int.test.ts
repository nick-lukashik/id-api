import { createAccessTokenVerifier, InvalidTokenError } from '@nick-lukashik/auth'
import { sql } from 'drizzle-orm'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { RolesService } from '../src/users/roles.service.js'
import { INTERNAL_TOKEN, startApp, type TestApp } from './harness.js'

let t: TestApp

beforeAll(async () => {
    t = await startApp()
})
afterAll(async () => {
    await t?.close()
})

/** Signs in through both steps and returns the session tokens. */
async function signIn(email: string, ip = '203.0.113.10') {
    const started = await t
        .http()
        .post('/api/v1/login/email')
        .set('x-forwarded-for', ip)
        .send({
            email,
            locale: 'ru',
        })
        .expect(202)
    const { code, challengeId } = t.delivery.last()
    expect(started.body.challengeId).toBe(challengeId)
    const verified = await t
        .http()
        .post('/api/v1/login/email/verify')
        .set('x-forwarded-for', ip)
        .send({
            challengeId,
            code,
        })
        .expect(200)
    return verified.body as {
        accessToken: string
        refreshToken: string
        sessionId: string
        user: {
            id: string
            email: string
            locale: string
            roles: string[]
        }
    }
}

describe('sign-in by email code', () => {
    it('creates the user on the first correct code, issues tokens and an event', async () => {
        const session = await signIn('Anna@Example.com')
        expect(session.user.email).toBe('anna@example.com')
        expect(session.user.locale).toBe('ru')

        const me = await t.http().get('/api/v1/me').set('authorization', `Bearer ${session.accessToken}`).expect(200)
        expect(me.body).toMatchObject({
            email: 'anna@example.com',
            roles: [],
        })

        const events = await t.db.execute<{
            type: string
        }>(sql`select type from outbox`)
        expect(events.rows.map(row => row.type)).toContain('id.user.registered.v1')
    })

    it('stores only a hash of the code and accepts it once', async () => {
        await t.http().post('/api/v1/login/email').send({
            email: 'once@example.com',
        })
        const { code, challengeId } = t.delivery.last()
        const stored = await t.db.execute<{
            code_hash: string
        }>(sql`select code_hash from login_challenges where id = ${challengeId}`)
        expect(stored.rows[0]?.code_hash).not.toContain(code)
        await t
            .http()
            .post('/api/v1/login/email/verify')
            .send({
                challengeId,
                code,
            })
            .expect(200)
        await t
            .http()
            .post('/api/v1/login/email/verify')
            .send({
                challengeId,
                code,
            })
            .expect(422)
    })

    it('locks a challenge after five wrong codes', async () => {
        await t.http().post('/api/v1/login/email').set('x-forwarded-for', '203.0.113.20').send({
            email: 'guess@example.com',
        })
        const { code, challengeId } = t.delivery.last()
        const wrong = code === '000000' ? '111111' : '000000'
        for (let attempt = 1; attempt <= 5; attempt++) {
            const response = await t
                .http()
                .post('/api/v1/login/email/verify')
                .set('x-forwarded-for', '203.0.113.20')
                .send({
                    challengeId,
                    code: wrong,
                })
                .expect(422)
            expect(response.body.details[0].message).toBe(attempt < 5 ? 'invalid_code' : 'too_many_attempts')
        }
        const late = await t
            .http()
            .post('/api/v1/login/email/verify')
            .set('x-forwarded-for', '203.0.113.20')
            .send({
                challengeId,
                code,
            })
            .expect(422)
        expect(late.body.details[0].message).toBe('too_many_attempts')
    })

    it('answers the same for unknown and known emails and validates input', async () => {
        const known = await t.http().post('/api/v1/login/email').send({
            email: 'anna@example.com',
        })
        const unknown = await t.http().post('/api/v1/login/email').send({
            email: 'nobody@example.com',
        })
        expect(Object.keys(known.body).sort()).toEqual(Object.keys(unknown.body).sort())
        await t
            .http()
            .post('/api/v1/login/email')
            .send({
                email: 'not-an-email',
            })
            .expect(400)
    })
})

describe('sessions', () => {
    it('rotates refresh tokens, retries within the grace window and burns a reused family', async () => {
        const session = await signIn('rotate@example.com')
        const first = await t
            .http()
            .post('/api/v1/sessions/refresh')
            .send({
                refreshToken: session.refreshToken,
            })
            .expect(200)
        expect(first.body.refreshToken).not.toBe(session.refreshToken)

        // Two tabs: the previous token within the grace window gets the same new token.
        const retry = await t
            .http()
            .post('/api/v1/sessions/refresh')
            .send({
                refreshToken: session.refreshToken,
            })
            .expect(200)
        expect(retry.body.refreshToken).toBe(first.body.refreshToken)

        const second = await t
            .http()
            .post('/api/v1/sessions/refresh')
            .send({
                refreshToken: first.body.refreshToken,
            })
            .expect(200)
        // The token from two rotations ago is outside any grace: reuse ends the session.
        await t
            .http()
            .post('/api/v1/sessions/refresh')
            .send({
                refreshToken: session.refreshToken,
            })
            .expect(401)
        await t
            .http()
            .post('/api/v1/sessions/refresh')
            .send({
                refreshToken: second.body.refreshToken,
            })
            .expect(401)
        const revoked = await t.db.execute<{
            revoked_reason: string
        }>(sql`select revoked_reason from sessions where id = ${session.sessionId}`)
        expect(revoked.rows[0]?.revoked_reason).toBe('reuse_detected')
    })

    it('ends a session on logout and lists and revokes the others', async () => {
        const a = await signIn('multi@example.com', '203.0.113.30')
        const b = await signIn('multi@example.com', '203.0.113.31')
        const list = await t
            .http()
            .get('/api/v1/me/sessions')
            .set('authorization', `Bearer ${a.accessToken}`)
            .expect(200)
        expect(list.body.items).toHaveLength(2)
        expect(list.body.items.find((item: { current: boolean }) => item.current).id).toBe(a.sessionId)

        await t
            .http()
            .post('/api/v1/me/sessions/revoke-others')
            .set('authorization', `Bearer ${a.accessToken}`)
            .expect(200, {
                revoked: 1,
            })
        await t
            .http()
            .post('/api/v1/sessions/refresh')
            .send({
                refreshToken: b.refreshToken,
            })
            .expect(401)

        await t
            .http()
            .post('/api/v1/sessions/logout')
            .send({
                refreshToken: a.refreshToken,
            })
            .expect(204)
        await t
            .http()
            .post('/api/v1/sessions/refresh')
            .send({
                refreshToken: a.refreshToken,
            })
            .expect(401)
    })

    it('refuses requests without a valid access token', async () => {
        await t.http().get('/api/v1/me').expect(401)
        await t.http().get('/api/v1/me').set('authorization', 'Bearer nope').expect(401)
    })
})

describe('keys, roles and internal calls', () => {
    it('publishes a JWKS that verifies its tokens through @nick-lukashik/auth', async () => {
        const session = await signIn('jwks@example.com')
        const verify = createAccessTokenVerifier({
            jwksUrl: `${t.url}/.well-known/jwks.json`,
            issuer: 'https://id.example.test',
            audience: 'nick-lukashik',
        })
        const claims = await verify(session.accessToken)
        expect(claims.userId).toBe(session.user.id)
        expect(claims.sessionId).toBe(session.sessionId)

        const otherAudience = createAccessTokenVerifier({
            jwksUrl: `${t.url}/.well-known/jwks.json`,
            issuer: 'https://id.example.test',
            audience: 'someone-else',
        })
        await expect(otherAudience(session.accessToken)).rejects.toBeInstanceOf(InvalidTokenError)
    })

    it('puts a granted role into the next token', async () => {
        const session = await signIn('owner@example.com')
        await t.app.get(RolesService).grant('owner@example.com', 'owner', 'test', 'test')
        const refreshed = await t
            .http()
            .post('/api/v1/sessions/refresh')
            .send({
                refreshToken: session.refreshToken,
            })
            .expect(200)
        const me = await t
            .http()
            .get('/api/v1/me')
            .set('authorization', `Bearer ${refreshed.body.accessToken}`)
            .expect(200)
        expect(me.body.roles).toEqual([
            'owner',
        ])
    })

    it('serves users to in-cluster callers with the service token only', async () => {
        const session = await signIn('internal@example.com')
        await t.http().get(`/api/v1/internal/users/${session.user.id}`).expect(401)
        const user = await t
            .http()
            .get(`/api/v1/internal/users/${session.user.id}`)
            .set('authorization', `Bearer ${INTERNAL_TOKEN}`)
            .expect(200)
        expect(user.body).toMatchObject({
            email: 'internal@example.com',
            locale: 'ru',
            status: 'active',
        })
    })
})
