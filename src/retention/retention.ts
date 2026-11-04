import { type BeforeApplicationShutdown, Inject, Injectable, Logger, type OnApplicationBootstrap } from '@nestjs/common'
import type { ConfigType } from '@nestjs/config'
import { and, inArray, isNull, lt, or, sql } from 'drizzle-orm'
import { DB } from '../common/database/database.js'
import { tokenConfig } from '../config/config.js'
import { authorizationCodes, loginChallenges, sessions } from '../db/schema.js'
import type { Db, Tx } from '../db/types.js'

const HOUR_MS = 3_600_000
const DAY_MS = 24 * HOUR_MS

// How long sign-in data is kept once it is no longer needed. The privacy
// policy quotes these periods: change them together.
/** A sign-in code request (the email in clear, an HMAC of the code): 24 hours after it was made. */
export const LOGIN_CHALLENGE_RETENTION_MS = 24 * HOUR_MS
/** A signed-out or revoked session: 90 days after it ended. */
export const REVOKED_SESSION_RETENTION_MS = 90 * DAY_MS
/** A session nobody ended: 90 days after its refresh token expired (last activity + refresh lifetime). */
export const EXPIRED_SESSION_RETENTION_MS = 90 * DAY_MS
/** A sign-in code of another app: 1 day after it expired. */
export const AUTHORIZATION_CODE_RETENTION_MS = DAY_MS

const PASS_INTERVAL_MS = HOUR_MS
/** The first pass, soon after start: a pod may not live an hour. */
const FIRST_PASS_DELAY_MS = 60_000
/** Rows per statement, well within the statement budget. */
const BATCH_SIZE = 1_000
/** `pg_try_advisory_xact_lock(hashtext(...))`, taken per batch: one replica deletes at a time. */
export const RETENTION_LOCK = 'id-api:retention'

export type Purged = {
    loginChallenges: number
    sessions: number
    authorizationCodes: number
}

type DeleteBatch = (tx: Tx) => PromiseLike<{
    rowCount: number | null
}>

/**
 * Deletes sign-in data past its retention: hourly on every replica. Every batch
 * commits by itself under an advisory lock, so a backlog holds no locks for long
 * and a failure keeps what was deleted before it. A replica that finds the lock
 * taken leaves the rest to the other one. `sessions.parent_session_id` has no
 * foreign key: a site's session outlives an idle id-web session it signed in
 * from and goes by its own dates.
 */
@Injectable()
export class Retention implements OnApplicationBootstrap, BeforeApplicationShutdown {
    private readonly logger = new Logger('Retention')
    private timer: NodeJS.Timeout | undefined
    private running: Promise<void> | undefined
    private stopped = false

    constructor(
        @Inject(DB) private readonly db: Db,
        @Inject(tokenConfig.KEY) private readonly token: ConfigType<typeof tokenConfig>,
    ) {}

    onApplicationBootstrap() {
        this.schedule(FIRST_PASS_DELAY_MS)
    }

    async beforeApplicationShutdown() {
        this.stopped = true
        clearTimeout(this.timer)
        await this.running
    }

    /**
     * One pass as of `now`: null when another replica holds the lock at the start;
     * when it takes the lock later, the pass stops there and returns what it deleted.
     */
    async purge(now: Date): Promise<Purged | null> {
        const before = (ms: number) => new Date(now.getTime() - ms)
        const challengeCutoff = before(LOGIN_CHALLENGE_RETENTION_MS)
        const revokedCutoff = before(REVOKED_SESSION_RETENTION_MS)
        const idleCutoff = before(this.token.refreshTtlSec * 1000 + EXPIRED_SESSION_RETENTION_MS)
        const codeCutoff = before(AUTHORIZATION_CODE_RETENTION_MS)
        const batches: [
            keyof Purged,
            DeleteBatch,
        ][] = [
            [
                'loginChallenges',
                tx =>
                    tx.delete(loginChallenges).where(
                        inArray(
                            loginChallenges.id,
                            tx
                                .select({
                                    id: loginChallenges.id,
                                })
                                .from(loginChallenges)
                                .where(lt(loginChallenges.createdAt, challengeCutoff))
                                .limit(BATCH_SIZE),
                        ),
                    ),
            ],
            [
                'sessions',
                tx =>
                    tx.delete(sessions).where(
                        inArray(
                            sessions.id,
                            tx
                                .select({
                                    id: sessions.id,
                                })
                                .from(sessions)
                                .where(
                                    or(
                                        lt(sessions.revokedAt, revokedCutoff),
                                        and(isNull(sessions.revokedAt), lt(sessions.lastActiveAt, idleCutoff)),
                                    ),
                                )
                                .limit(BATCH_SIZE),
                        ),
                    ),
            ],
            [
                'authorizationCodes',
                tx =>
                    tx.delete(authorizationCodes).where(
                        inArray(
                            authorizationCodes.codeHash,
                            tx
                                .select({
                                    codeHash: authorizationCodes.codeHash,
                                })
                                .from(authorizationCodes)
                                .where(lt(authorizationCodes.expiresAt, codeCutoff))
                                .limit(BATCH_SIZE),
                        ),
                    ),
            ],
        ]
        const purged: Purged = {
            loginChallenges: 0,
            sessions: 0,
            authorizationCodes: 0,
        }
        let started = false
        for (const [table, deleteBatch] of batches) {
            // Until a batch comes back short; a shutdown stops between batches.
            for (;;) {
                const count = await this.inOwnTransaction(deleteBatch)
                if (count === null) return started ? purged : null
                started = true
                purged[table] += count
                if (this.stopped) return purged
                if (count < BATCH_SIZE) break
            }
        }
        return purged
    }

    /** One batch, committed by itself: the rows it deleted, or null when another replica holds the lock. */
    private inOwnTransaction(deleteBatch: DeleteBatch) {
        return this.db.transaction(async tx => {
            const { rows } = await tx.execute<{
                locked: boolean
            }>(sql`select pg_try_advisory_xact_lock(hashtext(${RETENTION_LOCK})) as locked`)
            if (!rows[0]?.locked) return null
            return (await deleteBatch(tx)).rowCount ?? 0
        })
    }

    private schedule(delayMs: number) {
        if (this.stopped) return
        this.timer = setTimeout(() => {
            this.running = this.pass().finally(() => {
                this.running = undefined
                this.schedule(PASS_INTERVAL_MS)
            })
        }, delayMs)
    }

    private async pass() {
        try {
            const purged = await this.purge(new Date())
            if (purged && purged.loginChallenges + purged.sessions + purged.authorizationCodes > 0)
                this.logger.log(purged, 'Expired sign-in data deleted')
        } catch (error) {
            this.logger.error(
                {
                    err: (error as Error).message,
                },
                'Retention pass failed',
            )
        }
    }
}
