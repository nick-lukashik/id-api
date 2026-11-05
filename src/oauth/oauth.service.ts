import { createHash, randomBytes } from 'node:crypto'
import { Inject, Injectable } from '@nestjs/common'
import type { ConfigType } from '@nestjs/config'
import { and, eq, gt, isNull, lt } from 'drizzle-orm'
import { DB } from '../common/database/database.js'
import { AppError } from '../common/http/app-error.js'
import { oauthConfig } from '../config/config.js'
import { authorizationCodes, sessions, users } from '../db/schema.js'
import type { Db } from '../db/types.js'
import { SessionsService } from '../sessions/sessions.service.js'
import type { ClientContext } from '../users/client-context.js'

const sha256 = (value: string) => createHash('sha256').update(value).digest()

const invalid = (path: string, reason: string) =>
    new AppError('UNPROCESSABLE', 'Sign-in request refused', [
        {
            path,
            message: reason,
        },
    ])
const invalidGrant = () => invalid('code', 'invalid_grant')

/**
 * Sign-in of the platform's apps through id-web: an authorization code bound
 * to a registered client, its exact redirect URI and a PKCE S256 challenge.
 * Each app gets its own session (`client_id`), so signing out of one app
 * leaves the others alone and "sign out everywhere" reaches them all. A
 * deliberately small flow between first-party apps, not a public OIDC server.
 */
@Injectable()
export class OAuthService {
    constructor(
        @Inject(DB) private readonly db: Db,
        @Inject(oauthConfig.KEY) private readonly config: ConfigType<typeof oauthConfig>,
        private readonly sessions: SessionsService,
    ) {}

    /** The registered client, only with a redirect URI it registered exactly. */
    client(clientId: string, redirectUri: string) {
        const client = this.config.clients.find(item => item.id === clientId)
        if (!client?.redirectUris.includes(redirectUri)) throw invalid('redirectUri', 'unregistered')
        return {
            id: client.id,
        }
    }

    /** A one-time code for the signed-in user, valid for 60 seconds. */
    async authorize(
        caller: {
            userId: string
            sessionId: string
        },
        input: {
            clientId: string
            redirectUri: string
            codeChallenge: string
        },
    ) {
        this.client(input.clientId, input.redirectUri)
        // Only the id-web session a person signed in to signs them in to a site. A site's
        // own token cannot make a session of its own: a sign-out would not reach that far.
        const session = await this.sessions.active(caller.userId, caller.sessionId)
        if (!session) throw new AppError('UNAUTHORIZED', 'Session ended, sign in again')
        if (session.clientId !== null || session.parentSessionId !== null)
            throw new AppError('FORBIDDEN', 'Only an id-web session signs in to a site')
        const code = randomBytes(32).toString('base64url')
        const expiresAt = new Date(Date.now() + this.config.codeTtlMs)
        // Spent and expired codes are no use to anyone; each new one sweeps them.
        await this.db.delete(authorizationCodes).where(lt(authorizationCodes.expiresAt, new Date()))
        await this.db.insert(authorizationCodes).values({
            codeHash: sha256(code).toString('hex'),
            clientId: input.clientId,
            redirectUri: input.redirectUri,
            codeChallenge: input.codeChallenge,
            sessionId: caller.sessionId,
            userId: caller.userId,
            expiresAt,
        })
        return {
            code,
            expiresAt: expiresAt.toISOString(),
        }
    }

    /**
     * The code for the app's own session. A wrong client, redirect or PKCE
     * verifier, an expired code or a second use all fail before any session
     * exists, and a failed attempt spends the code too.
     */
    async exchange(
        input: {
            clientId: string
            redirectUri: string
            code: string
            codeVerifier: string
        },
        client: ClientContext,
    ) {
        const now = new Date()
        const [consumed] = await this.db
            .update(authorizationCodes)
            .set({
                consumedAt: now,
            })
            .where(
                and(
                    eq(authorizationCodes.codeHash, sha256(input.code).toString('hex')),
                    isNull(authorizationCodes.consumedAt),
                    gt(authorizationCodes.expiresAt, now),
                ),
            )
            .returning()
        if (!consumed) throw invalidGrant()
        const challenge = sha256(input.codeVerifier).toString('base64url')
        if (
            consumed.clientId !== input.clientId
            || consumed.redirectUri !== input.redirectUri
            || consumed.codeChallenge !== challenge
        )
            throw invalidGrant()
        const sessionId = await this.db.transaction(async tx => {
            const [user] = await tx
                .select({
                    status: users.status,
                })
                .from(users)
                .where(eq(users.id, consumed.userId))
            if (user?.status !== 'active') throw invalidGrant()
            // Signed out at id-web since the code was issued: nothing to sign in from.
            // Locked until the site's session is in, as a sign-out locks it: one waits for the other.
            const [parent] = await tx
                .select({
                    id: sessions.id,
                })
                .from(sessions)
                .where(
                    and(
                        eq(sessions.id, consumed.sessionId),
                        isNull(sessions.revokedAt),
                        isNull(sessions.clientId),
                        isNull(sessions.parentSessionId),
                    ),
                )
                .for('update')
            if (!parent) throw invalidGrant()
            return this.sessions.create(tx, consumed.userId, client, 'sso', {
                clientId: consumed.clientId,
                parentSessionId: parent.id,
            })
        })
        return this.sessions.issue(sessionId, consumed.userId)
    }
}
