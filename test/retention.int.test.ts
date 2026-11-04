import { randomBytes, randomUUID } from 'node:crypto'
import { sql } from 'drizzle-orm'
import type pg from 'pg'
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
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

describe('retention batches', () => {
    /** More than one batch of them (BATCH_SIZE in retention.ts is 1000). */
    const OLD_CHALLENGES = 1_500

    async function oldChallenges(count: number) {
        const createdAt = ago(25 * HOUR)
        await t.db.insert(loginChallenges).values(
            Array.from(
                {
                    length: count,
                },
                () => {
                    const id = randomUUID()
                    return {
                        id,
                        email: `${id}@example.com`,
                        codeHash: 'h'.repeat(64),
                        locale: 'en',
                        createdAt,
                        expiresAt: new Date(createdAt.getTime() + 600_000),
                    } as const
                },
            ),
        )
    }

    /** The database refuses to delete rows of `table` after the first `allowed`, across transactions. */
    async function refuseDeletes(table: 'login_challenges' | 'sessions', allowed: number) {
        await t.db.execute(sql.raw('create sequence retention_test_deleted'))
        await t.db.execute(
            sql.raw(`
                create function retention_test_refuse() returns trigger language plpgsql as $$
                begin
                    if nextval('retention_test_deleted') > ${allowed} then
                        raise exception 'delete refused';
                    end if;
                    return old;
                end $$
            `),
        )
        await t.db.execute(
            sql.raw(
                `create trigger retention_test_refuse before delete on ${table} for each row execute function retention_test_refuse()`,
            ),
        )
        return () => t.db.execute(sql.raw(`drop trigger retention_test_refuse on ${table}`))
    }

    let allowDeletes: (() => Promise<unknown>) | undefined

    afterEach(async () => {
        await allowDeletes?.()
        allowDeletes = undefined
        await t.db.execute(sql.raw('drop function if exists retention_test_refuse'))
        await t.db.execute(sql.raw('drop sequence if exists retention_test_deleted'))
        // Whatever a test left over: the next one counts from none.
        await retention.purge(now)
    })

    it('commits every batch: a failure keeps what the batches before it deleted', async () => {
        await oldChallenges(OLD_CHALLENGES)
        allowDeletes = await refuseDeletes('login_challenges', 1_000)

        await expect(retention.purge(now)).rejects.toThrow()
        expect((await remaining()).challenges).toHaveLength(OLD_CHALLENGES - 1_000)
    })

    it('keeps the deletes of one table when a later table fails', async () => {
        const [user] = await t.db
            .insert(users)
            .values({
                email: `${randomUUID()}@example.com`,
            })
            .returning({
                id: users.id,
            })
        if (!user) throw new Error('no user row')
        const old = await challenge(ago(25 * HOUR))
        const revoked = await session(user.id, {
            lastActiveAt: ago(91 * DAY),
            revokedAt: ago(90 * DAY + HOUR),
        })
        allowDeletes = await refuseDeletes('sessions', 0)

        const purged = {
            loginChallenges: 0,
            sessions: 0,
            authorizationCodes: 0,
        }
        await expect(retention.purge(now, purged)).rejects.toThrow()
        const left = await remaining()
        expect(left.challenges).not.toContain(old)
        expect(left.sessions).toContain(revoked)
        // What the failed pass had deleted is still known: its log line says it.
        expect(purged.loginChallenges).toBeGreaterThanOrEqual(1)
    })

    it('stops after the batch under way on a shutdown', async () => {
        await oldChallenges(OLD_CHALLENGES)
        const stopping = new Retention(t.db, {
            refreshTtlSec: REFRESH_TTL / 1_000,
        } as never)
        await stopping.beforeApplicationShutdown()

        expect(await stopping.purge(now)).toEqual({
            loginChallenges: 1_000,
            sessions: 0,
            authorizationCodes: 0,
        })
    })

    it('stops when another replica takes the lock between batches, and reports what it deleted', async () => {
        await oldChallenges(OLD_CHALLENGES)
        const other = await t.app.get<pg.Pool>(PG_POOL).connect()
        try {
            const transaction = t.db.transaction.bind(t.db) as (...args: unknown[]) => Promise<unknown>
            vi.spyOn(t.db, 'transaction').mockImplementationOnce((async (...args: unknown[]) => {
                const result = await transaction(...args)
                await other.query('begin')
                await other.query('select pg_advisory_xact_lock(hashtext($1))', [
                    RETENTION_LOCK,
                ])
                return result
            }) as never)

            expect(await retention.purge(now)).toEqual({
                loginChallenges: 1_000,
                sessions: 0,
                authorizationCodes: 0,
            })
            expect((await remaining()).challenges).toHaveLength(OLD_CHALLENGES - 1_000)
        } finally {
            await other.query('rollback')
            other.release()
        }
    })
})
