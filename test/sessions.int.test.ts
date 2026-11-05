import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { setTimeout as sleep } from 'node:timers/promises'
import { eq, sql } from 'drizzle-orm'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { AppError } from '../src/common/http/app-error.js'
import { authorizationCodes, sessions } from '../src/db/schema.js'
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

    it('marks the sites of this browser, which ending the others leaves', async () => {
        const me = await signIn('sites@example.com')
        const other = await signIn('sites@example.com')
        const [site] = await t.db
            .insert(sessions)
            .values({
                userId: me.user.id,
                authMethod: 'sso',
                clientId: 'landing-web',
                parentSessionId: me.sessionId,
            })
            .returning({
                id: sessions.id,
            })
        if (!site) throw new Error('no site session')

        const list = await t.http().get('/api/v1/me/sessions').set('authorization', bearer(me)).expect(200)
        expect(
            Object.fromEntries(
                list.body.items.map((item: { id: string; thisBrowser: boolean }) => [
                    item.id,
                    item.thisBrowser,
                ]),
            ),
        ).toEqual({
            [me.sessionId]: false,
            [other.sessionId]: false,
            [site.id]: true,
        })

        await t.http().post('/api/v1/me/sessions/revoke-others').set('authorization', bearer(me)).expect(200, {
            revoked: 1,
        })
        const after = await t.http().get('/api/v1/me/sessions').set('authorization', bearer(me)).expect(200)
        expect(after.body.items.map((item: { id: string }) => item.id).sort()).toEqual(
            [
                me.sessionId,
                site.id,
            ].sort(),
        )
    })

    it('says at once that a session was ended, while its access token still opens the API', async () => {
        const me = await signIn('alive@example.com')
        const other = await signIn('alive@example.com')
        const active = (session: Tokens) =>
            t.http().get('/api/v1/me/session').set('authorization', bearer(session)).expect(200)
        await active(other).expect({
            active: true,
        })

        await t.http().delete(`/api/v1/me/sessions/${other.sessionId}`).set('authorization', bearer(me)).expect(204)

        await active(other).expect({
            active: false,
        })
        await active(me).expect({
            active: true,
        })
        await t.http().get('/api/v1/me').set('authorization', bearer(other)).expect(200)
    })

    it('answers 503, not that the session ended, when it cannot tell', async () => {
        const me = await signIn('alive-down@example.com')
        const down = vi.spyOn(t.app.get(RefreshStore), 'isLive').mockRejectedValue(new AppError('UNAVAILABLE', 'down'))
        await t.http().get('/api/v1/me/session').set('authorization', bearer(me)).expect(503)
        down.mockRestore()
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

    /** A site's session from a code of the id-web session. */
    async function siteSession(session: Tokens): Promise<Tokens> {
        const exchanged = await exchange(await authorize(session))
        expect(exchanged.status).toBe(200)
        return exchanged.body
    }

    it("refuses a code to a site's own session: only an id-web session signs in to a site", async () => {
        const web = await signIn('no-chain@example.com')
        const site = await siteSession(web)
        const pair = verifierPair()
        await t
            .http()
            .post('/api/v1/oauth/authorize')
            .set('authorization', bearer(site))
            .send({
                clientId: 'landing-web',
                redirectUri: SITE_CALLBACK,
                codeChallenge: pair.codeChallenge,
                codeChallengeMethod: 'S256',
            })
            .expect(403)
    })

    it('refuses a code to a session that has ended, while its access token still opens the API', async () => {
        const web = await signIn('ended-code@example.com')
        expect((await logout(web.refreshToken)).status).toBe(204)
        await t
            .http()
            .post('/api/v1/oauth/authorize')
            .set('authorization', bearer(web))
            .send({
                clientId: 'landing-web',
                redirectUri: SITE_CALLBACK,
                codeChallenge: verifierPair().codeChallenge,
                codeChallengeMethod: 'S256',
            })
            .expect(401)
    })

    it("refuses to exchange a code issued to a site's session before that was refused", async () => {
        const web = await signIn('old-code@example.com')
        const site = await siteSession(web)
        const pair = verifierPair()
        const code = randomBytes(32).toString('base64url')
        await t.db.insert(authorizationCodes).values({
            codeHash: createHash('sha256').update(code).digest('hex'),
            clientId: 'landing-web',
            redirectUri: SITE_CALLBACK,
            codeChallenge: pair.codeChallenge,
            sessionId: site.sessionId,
            userId: web.user.id,
            expiresAt: new Date(Date.now() + 60_000),
        })
        const refused = await exchange({
            code,
            codeVerifier: pair.codeVerifier,
        })
        expect(refused.status).toBe(422)
        expect(await liveChildren(site.sessionId)).toBe(0)
    })

    it("ends a session left under a site's session at its next refresh, with the sign-out or without", async () => {
        const web = await signIn('old-chain@example.com')
        const site = await siteSession(web)
        const [nested] = await t.db
            .insert(sessions)
            .values({
                userId: web.user.id,
                authMethod: 'sso',
                clientId: 'landing-web',
                parentSessionId: site.sessionId,
            })
            .returning({
                id: sessions.id,
            })
        if (!nested) throw new Error('no nested session')
        const tokens = await t.app.get(SessionsService).issue(nested.id, web.user.id)

        expect((await refresh(tokens.refreshToken)).status).toBe(401)
        expect((await revocation(nested.id))?.revokedReason).toBe('logout')
        expect((await refresh(site.refreshToken)).status).toBe(200)
    })

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

describe('an outage', () => {
    const refresh = (refreshToken: string) =>
        t.http().post('/api/v1/sessions/refresh').send({
            refreshToken,
        })

    // Each read of a refresh in turn. `email` keeps the signed-in users apart.
    it.each([
        [
            'the session',
            'select',
            1,
        ],
        [
            'the user',
            'select',
            2,
        ],
        [
            'the roles',
            'select',
            3,
        ],
        [
            'the grants',
            'selectDistinct',
            1,
        ],
    ] as const)('a refresh that fails on reading %s leaves the token as it was', async (_, method, failing) => {
        const session = await signIn(`postgres-down-${method}-${failing}@example.com`)
        const read = t.db[method].bind(t.db) as (...args: unknown[]) => unknown
        let reads = 0
        const down = vi.spyOn(t.db, method).mockImplementation(((...args: unknown[]) => {
            reads += 1
            if (reads === failing) throw new Error('Postgres is gone')
            return read(...args)
        }) as never)
        await refresh(session.refreshToken).expect(500)
        down.mockRestore()

        // Still the current token, not one in its grace window: a later try cannot read as reuse.
        expect(await t.redis.hGet(`rt:${session.sessionId}`, 'cur')).toBe(
            createHash('sha256').update(session.refreshToken).digest('hex'),
        )
        await refresh(session.refreshToken).expect(200)
    })

    it('a refresh that cannot note the last activity still succeeds', async () => {
        const session = await signIn('last-active-down@example.com')
        const update = t.db.update.bind(t.db)
        // Only the sessions table: the outbox relay writes in the background too.
        let tried = false
        const down = vi.spyOn(t.db, 'update').mockImplementation(((table: Parameters<typeof update>[0]) => {
            if (table !== sessions) return update(table)
            tried = true
            throw new Error('Postgres is gone')
        }) as typeof t.db.update)
        const { body } = await refresh(session.refreshToken).expect(200)
        expect(tried).toBe(true)
        down.mockRestore()
        expect(body.refreshToken).not.toBe(session.refreshToken)
    })

    it('a Postgres too slow to answer in time leaves the token as it was', async () => {
        const session = await signIn('postgres-slow@example.com')
        const select = t.db.select.bind(t.db)
        const now = Date.now
        const slow = vi.spyOn(t.db, 'select').mockImplementationOnce(((...args: Parameters<typeof select>) => {
            // The clock moves on while the read takes its time.
            vi.spyOn(Date, 'now').mockImplementation(() => now() + 9_000)
            return select(...args)
        }) as typeof t.db.select)
        await refresh(session.refreshToken).expect(503)
        vi.mocked(Date.now).mockRestore()
        slow.mockRestore()
        expect(await t.redis.hGet(`rt:${session.sessionId}`, 'cur')).toBe(
            createHash('sha256').update(session.refreshToken).digest('hex'),
        )
        await refresh(session.refreshToken).expect(200)
    })

    it('a reply of Redis that got lost does not lose the token', async () => {
        const session = await signIn('redis-reply-lost@example.com')
        const run = t.redis.eval.bind(t.redis)
        const lost = vi.spyOn(t.redis, 'eval').mockImplementationOnce((async (...args: Parameters<typeof run>) => {
            await run(...args)
            throw new Error('Redis command exceeded 500 ms')
        }) as typeof t.redis.eval)
        const { body } = await refresh(session.refreshToken).expect(200)
        lost.mockRestore()
        // The token Redis did turn to: the session goes on with it.
        await refresh(body.refreshToken).expect(200)
    })

    it.each([
        [
            'refresh',
            '/api/v1/sessions/refresh',
        ],
        [
            'sign-out',
            '/api/v1/sessions/logout',
        ],
    ])('a %s without Redis answers 503, the answer for a dependency that is down', async (_, path) => {
        const session = await signIn(`redis-down-${path.length}@example.com`)
        const down = vi.spyOn(t.redis, 'eval').mockImplementation(() => {
            throw new Error('The client is closed')
        })
        const { body } = await t
            .http()
            .post(path)
            .send({
                refreshToken: session.refreshToken,
            })
            .expect(503)
        down.mockRestore()
        expect(body.code).toBe('UNAVAILABLE')
    })
})
