import { Inject, Injectable, Logger } from '@nestjs/common'
import type { ConfigType } from '@nestjs/config'
import { and, desc, eq, gt, inArray, isNull, lt, ne, or } from 'drizzle-orm'
import { z } from 'zod'
import { DB } from '../common/database/database.js'
import { AppError } from '../common/http/app-error.js'
import { cursorCodec } from '../common/http/cursor.js'
import { tokenConfig } from '../config/config.js'
import { sessions } from '../db/schema.js'
import type { Db, SessionRow, Tx, UserRow } from '../db/types.js'
import { SigningKeys } from '../keys/signing-keys.js'
import type { ClientContext } from '../users/client-context.js'
import { GrantsService } from '../users/grants.service.js'
import { RolesService } from '../users/roles.service.js'
import { UsersService } from '../users/users.service.js'
import { familyOf, RefreshStore } from './refresh-store.js'

export type AuthMethod = 'email' | 'google' | 'passkey' | 'sso'

export type SessionTokens = {
    accessToken: string
    accessExpiresAt: string
    refreshToken: string
    sessionId: string
}

type RevokedReason = NonNullable<SessionRow['revokedReason']>
/** The token turns only with time to answer: a request has 10 s, and id-web waits as long. */
const ROTATE_DEADLINE_MS = 8_000
type Claims = Omit<Parameters<SigningKeys['sign']>[0], 'sessionId'>

const PAGE_SIZE = 50
const cursor = cursorCodec(
    z.object({
        lastActiveAt: z.iso.datetime(),
        id: z.uuid(),
    }),
)

@Injectable()
export class SessionsService {
    private readonly logger = new Logger('Sessions')

    constructor(
        @Inject(DB) private readonly db: Db,
        @Inject(tokenConfig.KEY) private readonly config: ConfigType<typeof tokenConfig>,
        private readonly refresh: RefreshStore,
        private readonly keys: SigningKeys,
        private readonly users: UsersService,
        private readonly roles: RolesService,
        private readonly grants: GrantsService,
    ) {}

    /**
     * The session row, inside the sign-in transaction. `site` names the app a
     * session belongs to and the id-web session it signed in from (sign-in
     * through id-web from another site).
     */
    async create(
        tx: Tx,
        userId: string,
        client: ClientContext,
        method: AuthMethod,
        site: {
            clientId: string
            parentSessionId: string
        } | null = null,
    ) {
        const [row] = await tx
            .insert(sessions)
            .values({
                userId,
                authMethod: method,
                clientId: site?.clientId ?? null,
                parentSessionId: site?.parentSessionId ?? null,
                ip: client.ip,
                userAgent: client.userAgent,
            })
            .returning({
                id: sessions.id,
            })
        if (!row) throw new Error('session insert returned nothing')
        return row.id
    }

    /** The first token pair of a committed session. */
    async issue(sessionId: string, userId: string): Promise<SessionTokens> {
        const claims = await this.claimsOf(await this.users.get(this.db, userId))
        const refreshToken = await this.refresh.issue(sessionId, this.config.refreshTtlSec)
        return this.signed(sessionId, claims, refreshToken)
    }

    /**
     * Rotates the refresh token; a reused one burns the session. All it needs from
     * Postgres is read first: a refresh that fails on it leaves the token as it was,
     * and an outage longer than the grace window cannot read as reuse afterwards.
     */
    async rotate(presented: string): Promise<SessionTokens> {
        const started = Date.now()
        const sessionId = familyOf(presented)
        const state = sessionId ? await this.refreshState(sessionId) : undefined
        // Too late to answer in time (a slow Postgres): the caller has given up and keeps this token.
        if (Date.now() - started > ROTATE_DEADLINE_MS) throw new AppError('UNAVAILABLE', 'Sessions are slow, retry')
        const rotated = await this.refresh.rotate(presented, {
            ttlSec: this.config.refreshTtlSec,
            graceMs: this.config.refreshGraceMs,
        })
        if (rotated.result === 'REUSE' && rotated.sessionId) {
            this.logger.warn(
                {
                    sessionId: rotated.sessionId,
                },
                'Refresh token reuse: session revoked',
            )
            await this.revoke(
                [
                    rotated.sessionId,
                ],
                'reuse_detected',
            )
        }
        if (rotated.result !== 'OK' && rotated.result !== 'RETRY') throw sessionEnded()

        if (!state) {
            await this.refresh.revoke([
                rotated.sessionId,
            ])
            throw sessionEnded()
        }
        if ('ended' in state) {
            await this.revoke(
                [
                    rotated.sessionId,
                ],
                state.ended,
            )
            throw sessionEnded()
        }
        void this.noteActivity(rotated.sessionId)
        return this.signed(rotated.sessionId, state.claims, rotated.token)
    }

    /**
     * What a refresh of this session comes to, as Postgres has it: undefined for a
     * session that is gone, the reason for one that has to end, or the token's claims.
     */
    private async refreshState(sessionId: string): Promise<
        | {
              ended: RevokedReason
          }
        | {
              claims: Claims
          }
        | undefined
    > {
        const [session] = await this.db
            .select()
            .from(sessions)
            .where(and(eq(sessions.id, sessionId), isNull(sessions.revokedAt)))
        if (!session) return undefined
        // A site's session ends with the id-web session it signed in from, also one a sign-out missed.
        if (session.parentSessionId) {
            const [parent] = await this.db
                .select({
                    revokedAt: sessions.revokedAt,
                    revokedReason: sessions.revokedReason,
                })
                .from(sessions)
                .where(eq(sessions.id, session.parentSessionId))
            if (!parent || parent.revokedAt)
                return {
                    ended: parent?.revokedReason ?? 'logout',
                }
        }
        const user = await this.users.get(this.db, session.userId)
        if (user.status !== 'active')
            return {
                ended: 'admin',
            }
        return {
            claims: await this.claimsOf(user),
        }
    }

    /** Only for the sessions list: the token has already turned, so this must not fail or delay the refresh. */
    private async noteActivity(sessionId: string) {
        try {
            await this.db
                .update(sessions)
                .set({
                    lastActiveAt: new Date(),
                })
                .where(eq(sessions.id, sessionId))
        } catch (error) {
            this.logger.warn(
                {
                    sessionId,
                    err: error,
                },
                'Last activity of a session not noted',
            )
        }
    }

    /**
     * Ends a session by its refresh token (sign-out): only by a token that still
     * opens it, never by the session id alone. Any other token is fine and changes nothing.
     */
    async logout(presented: string) {
        const sessionId = await this.refresh.sessionOf(presented)
        if (sessionId)
            await this.revoke(
                [
                    sessionId,
                ],
                'logout',
            )
    }

    /** Whether the session of an access token is still alive: the token says nothing of one ended since it was issued. */
    isLive(sessionId: string) {
        return this.refresh.isLive(sessionId)
    }

    /** A live session of this user, or undefined. */
    async active(userId: string, sessionId: string) {
        const [session] = await this.db
            .select()
            .from(sessions)
            .where(and(eq(sessions.id, sessionId), eq(sessions.userId, userId), isNull(sessions.revokedAt)))
        return session
    }

    /** The live sessions, most recently active first, 50 to a page; `from` is the previous page's `nextCursor`. */
    async list(userId: string, from?: string) {
        const after = from ? cursor.decode(from) : undefined
        const rows = await this.db
            .select({
                id: sessions.id,
                createdAt: sessions.createdAt,
                lastActiveAt: sessions.lastActiveAt,
                userAgent: sessions.userAgent,
                ip: sessions.ip,
                authMethod: sessions.authMethod,
                clientId: sessions.clientId,
                parentSessionId: sessions.parentSessionId,
            })
            .from(sessions)
            .where(
                and(
                    eq(sessions.userId, userId),
                    this.live(),
                    after
                        ? or(
                              lt(sessions.lastActiveAt, new Date(after.lastActiveAt)),
                              and(eq(sessions.lastActiveAt, new Date(after.lastActiveAt)), lt(sessions.id, after.id)),
                          )
                        : undefined,
                ),
            )
            .orderBy(desc(sessions.lastActiveAt), desc(sessions.id))
            .limit(PAGE_SIZE + 1)
        const items = rows.slice(0, PAGE_SIZE)
        const last = items.at(-1)
        return {
            items,
            nextCursor:
                rows.length > PAGE_SIZE && last
                    ? cursor.encode({
                          lastActiveAt: last.lastActiveAt.toISOString(),
                          id: last.id,
                      })
                    : null,
        }
    }

    /** Revokes one of the caller's own sessions; someone else's is 404. */
    async revokeOwn(userId: string, sessionId: string) {
        const [session] = await this.db
            .select({
                id: sessions.id,
            })
            .from(sessions)
            .where(and(eq(sessions.id, sessionId), eq(sessions.userId, userId), isNull(sessions.revokedAt)))
        if (!session) throw new AppError('NOT_FOUND', 'Session not found')
        await this.revoke(
            [
                session.id,
            ],
            'user',
        )
    }

    /** Every other session of the user, except the other sites' sessions of this browser (children of this one). */
    async revokeOthers(userId: string, currentSessionId: string) {
        const others = await this.db
            .select({
                id: sessions.id,
            })
            .from(sessions)
            .where(
                and(
                    eq(sessions.userId, userId),
                    ne(sessions.id, currentSessionId),
                    or(isNull(sessions.parentSessionId), ne(sessions.parentSessionId, currentSessionId)),
                    this.live(),
                ),
            )
        await this.revoke(
            others.map(row => row.id),
            'user',
        )
        return others.length
    }

    /**
     * Not ended and refreshed within the refresh lifetime: past it the Redis
     * family has expired, though nobody marked the row.
     */
    private live() {
        return and(
            isNull(sessions.revokedAt),
            gt(sessions.lastActiveAt, new Date(Date.now() - this.config.refreshTtlSec * 1_000)),
        )
    }

    /**
     * Ends sessions and the other sites' sessions signed in from them. The rows
     * stay locked from before the children are read until they are marked, and
     * a code exchange locks its parent the same way: it either commits its site
     * session first (and that one is among the children) or finds the parent ended.
     */
    private async revoke(ids: string[], reason: RevokedReason) {
        if (ids.length === 0) return
        await this.db.transaction(async tx => {
            // In id order, so two revocations over the same sessions cannot deadlock.
            await tx
                .select({
                    id: sessions.id,
                })
                .from(sessions)
                .where(inArray(sessions.id, ids))
                .orderBy(sessions.id)
                .for('update')
            const family = await this.withChildren(tx, ids)
            await this.refresh.revoke(family)
            await this.markRevoked(tx, family, reason)
        })
    }

    /** The sessions and their live children (one level: a site's session never has its own). */
    private async withChildren(tx: Tx, ids: string[]) {
        const children = await tx
            .select({
                id: sessions.id,
            })
            .from(sessions)
            .where(and(inArray(sessions.parentSessionId, ids), isNull(sessions.revokedAt)))
        return [
            ...new Set([
                ...ids,
                ...children.map(row => row.id),
            ]),
        ]
    }

    private async markRevoked(tx: Tx, ids: string[], reason: RevokedReason) {
        await tx
            .update(sessions)
            .set({
                revokedAt: new Date(),
                revokedReason: reason,
            })
            .where(and(inArray(sessions.id, ids), isNull(sessions.revokedAt)))
    }

    /** What an access token says of the user: read from Postgres at every issuance. */
    private async claimsOf(user: Pick<UserRow, 'id' | 'accessVersion'>): Promise<Claims> {
        return {
            userId: user.id,
            roles: await this.roles.rolesOf(this.db, user.id),
            grants: await this.grants.activeOf(this.db, user.id),
            accessVersion: user.accessVersion,
        }
    }

    private async signed(sessionId: string, claims: Claims, refreshToken: string): Promise<SessionTokens> {
        const access = await this.keys.sign(
            {
                ...claims,
                sessionId,
            },
            new Date(),
        )
        return {
            accessToken: access.token,
            accessExpiresAt: access.expiresAt.toISOString(),
            refreshToken,
            sessionId,
        }
    }
}

const sessionEnded = () => new AppError('UNAUTHORIZED', 'Session ended, sign in again')
