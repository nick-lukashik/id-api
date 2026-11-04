import { randomBytes, randomUUID } from 'node:crypto'
import type pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { PG_POOL } from '../src/common/database/database.js'
import { authorizationCodes, loginChallenges, sessions, users } from '../src/db/schema.js'
import { RETENTION_LOCK, Retention } from '../src/retention/retention.js'
import { SITE_CALLBACK, startApp, type TestApp } from './harness.js'

const HOUR = 3_600_000
const DAY = 24 * HOUR
/** REFRESH_TOKEN_TTL_SECONDS of the test app (the default). */
const REFRESH_TTL = 30 * DAY

let t: TestApp
let retention: Retention

beforeAll(async () => {
    t = await startApp()
    retention = t.app.get(Retention)
})
afterAll(async () => {
    await t?.close()
})

/** The clock of the passes. Every row is an hour off a cutoff, either way. */
const now = new Date()
const ago = (ms: number) => new Date(now.getTime() - ms)

async function challenge(createdAt: Date) {
    const id = randomUUID()
    await t.db.insert(loginChallenges).values({
        id,
        email: `${id}@example.com`,
        codeHash: randomBytes(32).toString('hex'),
        locale: 'en',
        createdAt,
        expiresAt: new Date(createdAt.getTime() + 600_000),
    })
    return id
}

async function session(
    userId: string,
    dates: {
        lastActiveAt: Date
        revokedAt?: Date
        parentSessionId?: string
    },
) {
    const [row] = await t.db
        .insert(sessions)
        .values({
            userId,
            authMethod: 'email',
            clientId: dates.parentSessionId ? 'landing-web' : null,
            parentSessionId: dates.parentSessionId ?? null,
            createdAt: dates.lastActiveAt,
            lastActiveAt: dates.lastActiveAt,
            revokedAt: dates.revokedAt ?? null,
            revokedReason: dates.revokedAt ? 'logout' : null,
        })
        .returning({
            id: sessions.id,
        })
    if (!row) throw new Error('no session row')
    return row.id
}

async function authorizationCode(userId: string, expiresAt: Date) {
    const codeHash = randomBytes(32).toString('hex')
    await t.db.insert(authorizationCodes).values({
        codeHash,
        clientId: 'landing-web',
        redirectUri: SITE_CALLBACK,
        codeChallenge: randomBytes(32).toString('base64url'),
        sessionId: randomUUID(),
        userId,
        expiresAt,
    })
    return codeHash
}

const remaining = async () => ({
    challenges: (
        await t.db
            .select({
                id: loginChallenges.id,
            })
            .from(loginChallenges)
    )
        .map(row => row.id)
        .sort(),
    sessions: (
        await t.db
            .select({
                id: sessions.id,
            })
            .from(sessions)
    )
        .map(row => row.id)
        .sort(),
    codes: (
        await t.db
            .select({
                codeHash: authorizationCodes.codeHash,
            })
            .from(authorizationCodes)
    )
        .map(row => row.codeHash)
        .sort(),
})

describe('retention', () => {
    let rows: Record<string, string>

    beforeAll(async () => {
        const [user] = await t.db
            .insert(users)
            .values({
                email: 'kept@example.com',
            })
            .returning({
                id: users.id,
            })
        if (!user) throw new Error('no user row')
        const idleParent = await session(user.id, {
            lastActiveAt: ago(REFRESH_TTL + 90 * DAY + HOUR),
        })
        rows = {
            oldChallenge: await challenge(ago(24 * HOUR + HOUR)),
            newChallenge: await challenge(ago(24 * HOUR - HOUR)),
            revokedLongAgo: await session(user.id, {
                lastActiveAt: ago(91 * DAY),
                revokedAt: ago(90 * DAY + HOUR),
            }),
            revokedLately: await session(user.id, {
                lastActiveAt: ago(91 * DAY),
                revokedAt: ago(90 * DAY - HOUR),
            }),
            // Revoked a day ago after a long idle time: 90 days from the revocation, not from the last activity.
            revokedYesterday: await session(user.id, {
                lastActiveAt: ago(200 * DAY),
                revokedAt: ago(DAY),
            }),
            idleParent,
            idleLately: await session(user.id, {
                lastActiveAt: ago(REFRESH_TTL + 90 * DAY - HOUR),
            }),
            // A site's session lives on its own refresh token after the id-web session it came from went idle.
            child: await session(user.id, {
                lastActiveAt: ago(DAY),
                parentSessionId: idleParent,
            }),
            live: await session(user.id, {
                lastActiveAt: now,
            }),
            oldCode: await authorizationCode(user.id, ago(DAY + HOUR)),
            newCode: await authorizationCode(user.id, ago(DAY - HOUR)),
        }
    })

    const ids = (...names: string[]) => names.map(name => rows[name] as string).sort()

    it('leaves the pass to the replica that holds the lock', async () => {
        const before = await remaining()
        const other = await t.app.get<pg.Pool>(PG_POOL).connect()
        try {
            await other.query('begin')
            await other.query('select pg_advisory_xact_lock(hashtext($1))', [
                RETENTION_LOCK,
            ])
            expect(await retention.purge(now)).toBeNull()
        } finally {
            await other.query('rollback')
            other.release()
        }
        expect(await remaining()).toEqual(before)
    })

    it('deletes old sign-in codes, ended and long expired sessions and spent app codes, and keeps the rest', async () => {
        expect(await retention.purge(now)).toEqual({
            loginChallenges: 1,
            sessions: 2,
            authorizationCodes: 1,
        })
        expect(await remaining()).toEqual({
            challenges: ids('newChallenge'),
            sessions: ids('revokedLately', 'revokedYesterday', 'idleLately', 'child', 'live'),
            codes: ids('newCode'),
        })
    })

    it('counts from the clock it is given', async () => {
        expect(await retention.purge(new Date(now.getTime() + 2 * DAY))).toEqual({
            loginChallenges: 1,
            sessions: 2,
            authorizationCodes: 1,
        })
        expect(await remaining()).toEqual({
            challenges: [],
            sessions: ids('revokedYesterday', 'child', 'live'),
            codes: [],
        })
    })
})
