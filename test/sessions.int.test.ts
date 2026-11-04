import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { setTimeout as sleep } from 'node:timers/promises'
import { eq, sql } from 'drizzle-orm'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { sessions } from '../src/db/schema.js'
import { RefreshStore } from '../src/sessions/refresh-store.js'
import { SessionsService } from '../src/sessions/sessions.service.js'
import { SITE_CALLBACK, startApp, type TestApp } from './harness.js'

let t: TestApp

beforeAll(async () => {
    t = await startApp()
})
afterAll(async () => {
    await t?.close()
})

type Tokens = {
    accessToken: string
    refreshToken: string
    sessionId: string
    user: {
        id: string
    }
}

let signIns = 0

/** Signs in by email code, each time from another address (the per-IP limits stay out of the way). */
async function signIn(email: string): Promise<Tokens> {
    const ip = `203.0.113.${100 + signIns++}`
    await t
        .http()
        .post('/api/v1/login/email')
        .set('x-forwarded-for', ip)
        .send({
            email,
        })
        .expect(202)
    const { code, challengeId } = t.delivery.last()
    const verified = await t
        .http()
        .post('/api/v1/login/email/verify')
        .set('x-forwarded-for', ip)
        .send({
            challengeId,
            code,
        })
        .expect(200)
    return verified.body
}

const bearer = (session: { accessToken: string }) => `Bearer ${session.accessToken}`

// `.then` sends the request now, so a test can do other steps while it runs.
const refresh = (refreshToken: string) =>
    t
        .http()
        .post('/api/v1/sessions/refresh')
        .send({
            refreshToken,
        })
        .then(response => response)
const logout = (refreshToken: string) =>
    t
        .http()
        .post('/api/v1/sessions/logout')
        .send({
            refreshToken,
        })
        .then(response => response)

/** A real session id with a secret nobody was given: what anyone who saw a `sid` claim can make. */
const forged = (sessionId: string) => `${sessionId}.${randomBytes(32).toString('base64url')}`

async function revocation(sessionId: string) {
    const [row] = await t.db
        .select({
            revokedAt: sessions.revokedAt,
            revokedReason: sessions.revokedReason,
        })
        .from(sessions)
        .where(eq(sessions.id, sessionId))
    return row
}

/** A promise and the function that settles it: lets a test hold a step of the app. */
function gate() {
    let open!: () => void
    const opened = new Promise<void>(resolve => {
        open = resolve
    })
    return {
        open,
        opened,
    }
}

/** Resolves once a statement of this database waits for a row lock, or after `ms` when none does. */
async function rowLockWait(ms = 1_500) {
    const until = Date.now() + ms
    while (Date.now() < until) {
        const { rows } = await t.db.execute<{
            waiting: number
        }>(
            sql`select count(*)::int as waiting from pg_stat_activity where wait_event_type = 'Lock' and datname = current_database()`,
        )
        if ((rows[0]?.waiting ?? 0) > 0) return
        await sleep(20)
    }
}

describe('refresh tokens', () => {
    it('ignores a known session id with a made-up secret on refresh and on sign-out', async () => {
        const session = await signIn('forged@example.com')

        expect((await refresh(forged(session.sessionId))).status).toBe(401)
        const rotated = await refresh(session.refreshToken)
        expect(rotated.status).toBe(200)

        expect((await logout(forged(session.sessionId))).status).toBe(204)
        expect((await refresh(rotated.body.refreshToken)).status).toBe(200)
        expect(await revocation(session.sessionId)).toEqual({
            revokedAt: null,
            revokedReason: null,
        })
    })

    it('signs out with the previous token within the grace window too', async () => {
        const session = await signIn('grace-out@example.com')
        const rotated = await refresh(session.refreshToken)
        expect(rotated.status).toBe(200)

        expect((await logout(session.refreshToken)).status).toBe(204)
        expect((await refresh(rotated.body.refreshToken)).status).toBe(401)
        expect((await revocation(session.sessionId))?.revokedReason).toBe('logout')
    })

    it('remembers a superseded token for the refresh lifetime only', async () => {
        const store = t.app.get(RefreshStore)
        const options = {
            ttlSec: 3_600,
            graceMs: 0,
        }
        const first = await store.issue(randomUUID(), options.ttlSec)
        const second = await store.rotate(first, options)
        expect(second.result).toBe('OK')
        if (second.result !== 'OK') return

        // A token that would have expired by itself by now proves nothing: no reuse, the family lives on.
        const now = Date.now()
        vi.spyOn(Date, 'now').mockReturnValue(now + options.ttlSec * 1_000 + 1_000)
        expect((await store.rotate(first, options)).result).toBe('DEAD')
        expect((await store.rotate(second.token, options)).result).toBe('OK')
    })

    it('remembers the newest 512 superseded tokens only: an older one is dead, not reuse', async () => {
        const store = t.app.get(RefreshStore)
        const options = {
            ttlSec: 2_592_000,
            graceMs: 0,
        }
        const sessionId = randomUUID()
        // A clock that moves on: rotations within one millisecond would tie on the score.
        let now = Date.now()
        vi.spyOn(Date, 'now').mockImplementation(() => now)
        const tokens = [
            await store.issue(sessionId, options.ttlSec),
        ]
        for (let rotation = 0; rotation < 513; rotation++) {
            now += 1_000
            const rotated = await store.rotate(tokens.at(-1) as string, options)
            if (rotated.result !== 'OK') throw new Error(`rotation ${rotation}: ${rotated.result}`)
            tokens.push(rotated.token)
        }
        expect(await t.redis.zCard(`rtp:${sessionId}`)).toBe(512)

        // Past the cap: refused, and the family lives on.
        expect((await store.rotate(tokens[0] as string, options)).result).toBe('DEAD')
        expect(await store.sessionOf(tokens.at(-1) as string)).toBe(sessionId)
        expect(await t.redis.zCard(`rtp:${sessionId}`)).toBe(512)

        // The oldest one still kept burns the family.
        expect((await store.rotate(tokens[1] as string, options)).result).toBe('REUSE')
        expect(await store.sessionOf(tokens.at(-1) as string)).toBeNull()
        expect(await t.redis.exists(`rtp:${sessionId}`)).toBe(0)
    })
})

describe('session list', () => {
    it('lists only live sessions, most recently active first, 50 to a page', async () => {
        const me = await signIn('many@example.com')
        const hour = 3_600_000
        // 54 more sessions, two at each instant: the id orders them within it, also across the page break.
        const others = Array.from(
            {
                length: 54,
            },
            (_, index) => ({
                userId: me.user.id,
                authMethod: 'email' as const,
                lastActiveAt: new Date(Date.now() - hour - Math.floor(index / 2) * 60_000),
            }),
        )
        const inserted = await t.db.insert(sessions).values(others).returning({
            id: sessions.id,
            lastActiveAt: sessions.lastActiveAt,
        })
        await t.db.insert(sessions).values([
            {
                userId: me.user.id,
                authMethod: 'email',
                revokedAt: new Date(),
                revokedReason: 'user',
            },
            {
                // Not refreshed for longer than a refresh token lives (30 days): its Redis family is gone.
                userId: me.user.id,
                authMethod: 'email',
                lastActiveAt: new Date(Date.now() - 31 * 24 * hour),
            },
        ])
        const expected = inserted
            .sort((a, b) => b.lastActiveAt.getTime() - a.lastActiveAt.getTime() || (a.id < b.id ? 1 : -1))
            .map(row => row.id)

        const first = await t.http().get('/api/v1/me/sessions').set('authorization', bearer(me)).expect(200)
        expect(first.body.items).toHaveLength(50)
        expect(first.body.items[0]).toMatchObject({
            id: me.sessionId,
            current: true,
            authMethod: 'email',
        })
        expect(first.body.nextCursor).toEqual(expect.any(String))

        const second = await t
            .http()
            .get('/api/v1/me/sessions')
            .query({
                cursor: first.body.nextCursor,
            })
            .set('authorization', bearer(me))
            .expect(200)
        expect(second.body.nextCursor).toBeNull()
        expect(
            [
                ...first.body.items,
                ...second.body.items,
            ].map((item: { id: string }) => item.id),
        ).toEqual([
            me.sessionId,
            ...expected,
        ])

        await t
            .http()
            .get('/api/v1/me/sessions')
            .query({
                cursor: 'not-a-cursor',
            })
            .set('authorization', bearer(me))
            .expect(400)
    })

    it('ends only the live sessions when asked to end the others', async () => {
        const me = await signIn('others@example.com')
        await signIn('others@example.com')
        await t.db.insert(sessions).values({
            userId: me.user.id,
            authMethod: 'email',
            lastActiveAt: new Date(Date.now() - 31 * 24 * 3_600_000),
        })

        await t.http().post('/api/v1/me/sessions/revoke-others').set('authorization', bearer(me)).expect(200, {
            revoked: 1,
        })
    })
})

describe('site sessions and the sign-out of their id-web session', () => {
    const verifierPair = () => {
        const codeVerifier = randomBytes(48).toString('base64url')
        return {
            codeVerifier,
            codeChallenge: createHash('sha256').update(codeVerifier).digest('base64url'),
        }
    }

    /** A code for the site and the verifier that exchanges it. */
    async function authorize(session: Tokens) {
        const pair = verifierPair()
        const issued = await t
            .http()
            .post('/api/v1/oauth/authorize')
            .set('authorization', bearer(session))
            .send({
                clientId: 'landing-web',
                redirectUri: SITE_CALLBACK,
                codeChallenge: pair.codeChallenge,
                codeChallengeMethod: 'S256',
            })
            .expect(200)
        return {
            code: issued.body.code as string,
            codeVerifier: pair.codeVerifier,
        }
    }

    const exchange = (grant: { code: string; codeVerifier: string }) =>
        t
            .http()
            .post('/api/v1/oauth/token')
            .send({
                grantType: 'authorization_code',
                clientId: 'landing-web',
                redirectUri: SITE_CALLBACK,
                ...grant,
            })
            .then(response => response)

    async function liveChildren(parentSessionId: string) {
        const { rows } = await t.db.execute<{
            live: number
        }>(
            sql`select count(*)::int as live from sessions where parent_session_id = ${parentSessionId} and revoked_at is null`,
        )
        return rows[0]?.live
    }

    it('refuses an exchange that comes while the sign-out is under way', async () => {
        const session = await signIn('race-out-first@example.com')
        const grant = await authorize(session)

        // The sign-out holds between reading the site sessions and marking the rows.
        const store = t.app.get(RefreshStore)
        const revoke = store.revoke.bind(store)
        const reached = gate()
        const resume = gate()
        vi.spyOn(store, 'revoke').mockImplementationOnce(async ids => {
            reached.open()
            await resume.opened
            return revoke(ids)
        })
        const signedOut = logout(session.refreshToken)
        await reached.opened

        const exchanged = exchange(grant)
        await Promise.race([
            exchanged,
            rowLockWait(),
        ])
        resume.open()

        expect((await signedOut).status).toBe(204)
        const site = await exchanged
        expect(site.status).toBe(422)
        expect(await liveChildren(session.sessionId)).toBe(0)
    })

    it('ends the site session of an exchange the sign-out came in the middle of', async () => {
        const session = await signIn('race-exchange-first@example.com')
        const grant = await authorize(session)

        // The exchange holds after it found the id-web session alive, before the site's session is in.
        const service = t.app.get(SessionsService)
        const create = service.create.bind(service)
        const reached = gate()
        const resume = gate()
        vi.spyOn(service, 'create').mockImplementationOnce(async (...args) => {
            reached.open()
            await resume.opened
            return create(...args)
        })
        const exchanged = exchange(grant)
        await reached.opened

        const signedOut = logout(session.refreshToken)
        await Promise.race([
            signedOut,
            rowLockWait(),
        ])
        resume.open()

        const site = await exchanged
        expect(site.status).toBe(200)
        expect((await signedOut).status).toBe(204)
        // Ended by the sign-out itself, not only by the check of the next refresh.
        expect(await liveChildren(session.sessionId)).toBe(0)
        expect((await refresh(site.body.refreshToken)).status).toBe(401)
    })

    it('ends a site session whose id-web session ended without it', async () => {
        const session = await signIn('orphan@example.com')
        const site = await exchange(await authorize(session))
        expect(site.status).toBe(200)

        // What a sign-out racing the exchange could leave before: the parent ended, the site session not.
        await t.db
            .update(sessions)
            .set({
                revokedAt: new Date(),
                revokedReason: 'logout',
            })
            .where(eq(sessions.id, session.sessionId))

        expect((await refresh(site.body.refreshToken)).status).toBe(401)
        expect((await revocation(site.body.sessionId))?.revokedReason).toBe('logout')
    })
})
