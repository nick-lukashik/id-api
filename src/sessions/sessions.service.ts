import { Inject, Injectable, Logger } from '@nestjs/common'
import type { ConfigType } from '@nestjs/config'
import { and, desc, eq, inArray, isNull, ne } from 'drizzle-orm'
import { DB } from '../common/database/database.js'
import { AppError } from '../common/http/app-error.js'
import { tokenConfig } from '../config/config.js'
import { sessions } from '../db/schema.js'
import type { Db, Tx } from '../db/types.js'
import { SigningKeys } from '../keys/signing-keys.js'
import type { ClientContext } from '../users/client-context.js'
import { RolesService } from '../users/roles.service.js'
import { UsersService } from '../users/users.service.js'
import { RefreshStore } from './refresh-store.js'

export type AuthMethod = 'email' | 'google' | 'passkey' | 'sso'

export type SessionTokens = {
    accessToken: string
    accessExpiresAt: string
    refreshToken: string
    sessionId: string
}

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
    ) {}

    /**
     * The session row, inside the sign-in transaction. `clientId` names the app
     * a session belongs to (sign-in through id-web from another site).
     */
    async create(tx: Tx, userId: string, client: ClientContext, method: AuthMethod, clientId: string | null = null) {
        const [row] = await tx
            .insert(sessions)
            .values({
                userId,
                authMethod: method,
                clientId,
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
        const refreshToken = await this.refresh.issue(sessionId, this.config.refreshTtlSec)
        return this.tokens(sessionId, userId, refreshToken)
    }

    /** Rotates the refresh token; a reused one burns the session. */
    async rotate(presented: string): Promise<SessionTokens> {
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
            await this.markRevoked(
                [
                    rotated.sessionId,
                ],
                'reuse_detected',
            )
        }
        if (rotated.result !== 'OK' && rotated.result !== 'RETRY') throw sessionEnded()

        const [session] = await this.db
            .select()
            .from(sessions)
            .where(and(eq(sessions.id, rotated.sessionId), isNull(sessions.revokedAt)))
        if (!session) {
            await this.refresh.revoke([
                rotated.sessionId,
            ])
            throw sessionEnded()
        }
        const user = await this.users.get(this.db, session.userId)
        if (user.status !== 'active') {
            await this.revoke(
                [
                    session.id,
                ],
                'admin',
            )
            throw sessionEnded()
        }
        await this.db
            .update(sessions)
            .set({
                lastActiveAt: new Date(),
            })
            .where(eq(sessions.id, session.id))
        return this.tokens(session.id, session.userId, rotated.token)
    }

    /** Ends a session by its refresh token (sign-out); unknown tokens are fine. */
    async logout(presented: string) {
        const sessionId = presented.split('.')[0] ?? ''
        const [session] = await this.db
            .select({
                id: sessions.id,
            })
            .from(sessions)
            .where(and(eq(sessions.id, sessionId), isNull(sessions.revokedAt)))
            .catch(() => [])
        if (session)
            await this.revoke(
                [
                    session.id,
                ],
                'logout',
            )
    }

    /** A live session of this user, or undefined. */
    async active(userId: string, sessionId: string) {
        const [session] = await this.db
            .select()
            .from(sessions)
            .where(and(eq(sessions.id, sessionId), eq(sessions.userId, userId), isNull(sessions.revokedAt)))
        return session
    }

    list(userId: string) {
        return this.db
            .select({
                id: sessions.id,
                createdAt: sessions.createdAt,
                lastActiveAt: sessions.lastActiveAt,
                userAgent: sessions.userAgent,
                ip: sessions.ip,
                authMethod: sessions.authMethod,
                clientId: sessions.clientId,
            })
            .from(sessions)
            .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt)))
            .orderBy(desc(sessions.lastActiveAt))
            .limit(50)
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

    async revokeOthers(userId: string, currentSessionId: string) {
        const others = await this.db
            .select({
                id: sessions.id,
            })
            .from(sessions)
            .where(and(eq(sessions.userId, userId), ne(sessions.id, currentSessionId), isNull(sessions.revokedAt)))
        await this.revoke(
            others.map(row => row.id),
            'user',
        )
        return others.length
    }

    private async revoke(ids: string[], reason: 'logout' | 'user' | 'admin') {
        if (ids.length === 0) return
        await this.refresh.revoke(ids)
        await this.markRevoked(ids, reason)
    }

    private async markRevoked(ids: string[], reason: 'logout' | 'user' | 'admin' | 'reuse_detected') {
        await this.db
            .update(sessions)
            .set({
                revokedAt: new Date(),
                revokedReason: reason,
            })
            .where(and(inArray(sessions.id, ids), isNull(sessions.revokedAt)))
    }

    private async tokens(sessionId: string, userId: string, refreshToken: string): Promise<SessionTokens> {
        const user = await this.users.get(this.db, userId)
        const access = await this.keys.sign(
            {
                userId,
                sessionId,
                roles: await this.roles.rolesOf(this.db, userId),
                accessVersion: user.accessVersion,
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
