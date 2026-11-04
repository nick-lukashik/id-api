import { Inject, Injectable } from '@nestjs/common'
import type { ConfigType } from '@nestjs/config'
import type { AccessClaims } from '@nick-lukashik/auth'
import type { Locale } from '@nick-lukashik/contracts'
import { and, eq } from 'drizzle-orm'
import { DB } from '../common/database/database.js'
import { AppError } from '../common/http/app-error.js'
import { OutboxRelay } from '../common/messaging/outbox-relay.js'
import { webauthnConfig } from '../config/config.js'
import { identities, users } from '../db/schema.js'
import type { Db, Tx } from '../db/types.js'
import { RateLimiter } from '../login/rate-limiter.js'
import { SessionsService } from '../sessions/sessions.service.js'
import type { ClientContext } from '../users/client-context.js'
import { RolesService } from '../users/roles.service.js'
import { UsersService } from '../users/users.service.js'
import {
    type GoogleCode,
    type GoogleProfile,
    GoogleProvider,
    GoogleRejected,
    GoogleUnavailable,
} from './google.provider.js'

const refused = (path: string, reason: string, code: 'UNPROCESSABLE' | 'CONFLICT' | 'FORBIDDEN' = 'UNPROCESSABLE') =>
    new AppError(code, 'Google sign-in refused', [
        {
            path,
            message: reason,
        },
    ])

/**
 * Google as a sign-in method. Signing in and linking are separate: a Google
 * account whose email already has an account here is never attached to it by
 * itself (`link_required`); its owner signs in with the email code and links
 * it on the account page. The email code keeps working either way, so
 * unlinking never locks anyone out.
 */
@Injectable()
export class IdentitiesService {
    constructor(
        @Inject(DB) private readonly db: Db,
        @Inject(webauthnConfig.KEY) private readonly webauthn: ConfigType<typeof webauthnConfig>,
        private readonly google: GoogleProvider,
        private readonly users: UsersService,
        private readonly roles: RolesService,
        private readonly sessions: SessionsService,
        private readonly limiter: RateLimiter,
        private readonly relay: OutboxRelay,
    ) {}

    /** What id-web needs to send the browser to Google. */
    config() {
        return {
            enabled: this.google.enabled,
            authorizationEndpoint: this.google.authorizationEndpoint,
            clientId: this.google.clientId,
            redirectUri: this.google.redirectUri,
        }
    }

    /** A linked Google account signs in; an unknown one with a new email gets a new user. */
    async signIn(
        input: GoogleCode & {
            locale: Locale
        },
        client: ClientContext,
    ) {
        if (client.ip) await this.limiter.consume(`google-ip:${client.ip}`, 30, 600_000)
        const profile = await this.profile(input)
        const { user, sessionId } = await this.db.transaction(async tx => {
            let user = await this.linkedUser(tx, profile.subject)
            if (!user) {
                if (!profile.email || !profile.emailVerified) throw refused('email', 'unverified')
                const created = await this.users.create(tx, profile.email, input.locale, profile.name)
                if (created) {
                    await this.attach(tx, created.id, profile)
                    user = created
                } else {
                    // A concurrent first sign-in may have just created and linked it.
                    user = await this.linkedUser(tx, profile.subject)
                    if (!user) throw refused('email', 'link_required', 'CONFLICT')
                }
            }
            if (user.status !== 'active') throw new AppError('FORBIDDEN', 'Account suspended')
            return {
                user,
                sessionId: await this.sessions.create(tx, user.id, client, 'google'),
            }
        })
        this.relay.kick()
        const tokens = await this.sessions.issue(sessionId, user.id)
        return {
            ...tokens,
            user: this.users.toProfile(user, await this.roles.rolesOf(this.db, user.id)),
        }
    }

    /**
     * Links a Google account to the signed-in user. Like adding a passkey, only
     * an id-web session signed in at most `freshSignInMs` ago may: a stolen
     * older session cannot attach its own Google account and keep access after
     * that session is revoked. Otherwise the person signs in again.
     */
    async link(caller: AccessClaims, input: GoogleCode) {
        const session = await this.sessions.active(caller.userId, caller.sessionId)
        if (!session) throw new AppError('UNAUTHORIZED', 'Session ended, sign in again')
        const age = Date.now() - session.createdAt.getTime()
        if (session.clientId !== null || age > this.webauthn.freshSignInMs)
            throw refused('session', 'reauthentication_required', 'FORBIDDEN')
        const profile = await this.profile(input)
        await this.db.transaction(async tx => {
            const [existing] = await tx
                .select()
                .from(identities)
                .where(and(eq(identities.provider, 'google'), eq(identities.subject, profile.subject)))
            if (existing) {
                if (existing.userId === caller.userId) return
                throw refused('identity', 'in_use', 'CONFLICT')
            }
            if (!(await this.attach(tx, caller.userId, profile)))
                throw refused('identity', 'already_linked', 'CONFLICT')
        })
        return this.list(caller.userId)
    }

    async unlink(userId: string) {
        const removed = await this.db
            .delete(identities)
            .where(and(eq(identities.userId, userId), eq(identities.provider, 'google')))
            .returning({
                id: identities.id,
            })
        if (removed.length === 0) throw new AppError('NOT_FOUND', 'No Google account is linked')
    }

    async list(userId: string) {
        const rows = await this.db
            .select({
                provider: identities.provider,
                email: identities.email,
                createdAt: identities.createdAt,
            })
            .from(identities)
            .where(eq(identities.userId, userId))
        return {
            items: rows.map(row => ({
                provider: row.provider,
                email: row.email,
                linkedAt: row.createdAt.toISOString(),
            })),
        }
    }

    private async profile(input: GoogleCode): Promise<GoogleProfile> {
        if (!this.google.enabled) throw new AppError('NOT_FOUND', 'Google sign-in is off')
        try {
            return await this.google.verify(input)
        } catch (error) {
            if (error instanceof GoogleUnavailable) throw new AppError('UNAVAILABLE', 'Google is unreachable, retry')
            if (error instanceof GoogleRejected) throw refused('code', 'invalid_grant')
            throw error
        }
    }

    private async linkedUser(tx: Tx, subject: string) {
        const [row] = await tx
            .select({
                user: users,
            })
            .from(identities)
            .innerJoin(users, eq(users.id, identities.userId))
            .where(and(eq(identities.provider, 'google'), eq(identities.subject, subject)))
        return row?.user ?? null
    }

    /** The link; false when this user already has another Google account. */
    private async attach(tx: Tx, userId: string, profile: GoogleProfile) {
        const rows = await tx
            .insert(identities)
            .values({
                userId,
                provider: 'google',
                subject: profile.subject,
                email: profile.email,
            })
            .onConflictDoNothing()
            .returning({
                id: identities.id,
            })
        return rows.length > 0
    }
}
