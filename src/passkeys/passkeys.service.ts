import { Inject, Injectable, Logger } from '@nestjs/common'
import type { ConfigType } from '@nestjs/config'
import type { AccessClaims } from '@nick-lukashik/auth'
import {
    type AuthenticationResponseJSON,
    generateAuthenticationOptions,
    generateRegistrationOptions,
    type RegistrationResponseJSON,
    verifyAuthenticationResponse,
    verifyRegistrationResponse,
} from '@simplewebauthn/server'
import { and, asc, count, eq, or, sql } from 'drizzle-orm'
import { DB } from '../common/database/database.js'
import { AppError } from '../common/http/app-error.js'
import { OutboxRelay } from '../common/messaging/outbox-relay.js'
import { webauthnConfig } from '../config/config.js'
import { passkeys, users } from '../db/schema.js'
import type { Db, Tx } from '../db/types.js'
import { RateLimiter } from '../login/rate-limiter.js'
import { SessionsService } from '../sessions/sessions.service.js'
import type { ClientContext } from '../users/client-context.js'
import { RolesService } from '../users/roles.service.js'
import { UsersService } from '../users/users.service.js'
import { ChallengeStore } from './challenge-store.js'

/**
 * ES256, EdDSA and RS256, which every authenticator speaks. Left to its
 * default, SimpleWebAuthn offers ML-DSA first where Node supports it, with
 * signatures of several kilobytes.
 */
export const PASSKEY_ALGORITHMS = [
    -7,
    -8,
    -257,
]

/** WebAuthn transport hints worth keeping. */
const TRANSPORTS: readonly string[] = [
    'ble',
    'cable',
    'hybrid',
    'internal',
    'nfc',
    'smart-card',
    'usb',
]

type Passkey = typeof passkeys.$inferSelect

/**
 * The WebAuthn user handle of an account: the 16 bytes of its UUID. Stable
 * per user, so a device keeps one passkey per account, and it carries no
 * email or name.
 */
export const userHandleOf = (userId: string) => new Uint8Array(Buffer.from(userId.replaceAll('-', ''), 'hex'))
const handleString = (userId: string) => Buffer.from(userHandleOf(userId)).toString('base64url')

const refusal = (path: string, reason: string, code: 'UNPROCESSABLE' | 'CONFLICT' | 'FORBIDDEN' = 'UNPROCESSABLE') =>
    new AppError(code, 'Passkey not accepted', [
        {
            path,
            message: reason,
        },
    ])
/** Unknown, expired or already used: the browser starts over. */
const stale = () => refusal('challenge', 'stale')
/** The answer did not prove what it had to; why goes to the log only. */
const rejected = () => refusal('passkey', 'rejected')

/**
 * Passkeys with SimpleWebAuthn: RP `WEBAUTHN_RP_ID`, ceremonies accepted only
 * from `WEBAUTHN_ORIGIN`, user verification required both ways, one-time
 * challenges in Redis. A passkey sign-in is an ordinary session
 * (`auth_method = passkey`), so sign-in for the other apps works as after an
 * email code. The email code always stays, so removing a passkey never
 * locks anyone out.
 */
@Injectable()
export class PasskeysService {
    private readonly logger = new Logger('Passkeys')

    constructor(
        @Inject(DB) private readonly db: Db,
        @Inject(webauthnConfig.KEY) private readonly config: ConfigType<typeof webauthnConfig>,
        private readonly challenges: ChallengeStore,
        private readonly users: UsersService,
        private readonly roles: RolesService,
        private readonly sessions: SessionsService,
        private readonly limiter: RateLimiter,
        private readonly relay: OutboxRelay,
    ) {}

    /**
     * Creation options for the signed-in user. Only an id-web session signed in
     * at most `freshSignInMs` ago may add a passkey: a stolen older session
     * cannot plant its own key. Otherwise the person signs in again.
     */
    async registrationOptions(caller: AccessClaims) {
        await this.limiter.consume(`passkey-register:${caller.userId}`, 20, 3_600_000)
        const session = await this.sessions.active(caller.userId, caller.sessionId)
        if (!session) throw new AppError('UNAUTHORIZED', 'Session ended, sign in again')
        const age = Date.now() - session.createdAt.getTime()
        if (session.clientId !== null || age > this.config.freshSignInMs)
            throw refusal('session', 'reauthentication_required', 'FORBIDDEN')
        const user = await this.users.get(this.db, caller.userId)
        if (user.status !== 'active') throw new AppError('FORBIDDEN', 'Account suspended')

        const existing = await this.rows(user.id)
        if (existing.length >= this.config.maxPerUser) throw refusal('passkey', 'limit')
        const options = await generateRegistrationOptions({
            rpName: this.config.rpName,
            rpID: this.config.rpId,
            userID: userHandleOf(user.id),
            userName: user.email,
            userDisplayName: user.displayName ?? user.email,
            timeout: this.config.challengeTtlMs,
            attestationType: 'none',
            // The same device twice would replace its own passkey.
            excludeCredentials: existing.map(key => ({
                id: key.credentialId,
                transports: knownTransports(key.transports),
            })),
            authenticatorSelection: {
                residentKey: 'required',
                userVerification: 'required',
            },
            supportedAlgorithmIDs: PASSKEY_ALGORITHMS,
        })
        const challengeId = await this.challenges.put(
            'registration',
            {
                challenge: options.challenge,
                userId: user.id,
                sessionId: caller.sessionId,
            },
            this.config.challengeTtlMs,
        )
        return {
            challengeId,
            options,
        }
    }

    /** Verifies the new credential against the challenge of this user and session, then stores it. */
    async register(
        caller: AccessClaims,
        input: {
            challengeId: string
            name: string
            response: RegistrationResponseJSON
        },
    ) {
        const stored = await this.challenges.take('registration', input.challengeId)
        if (!stored || stored.userId !== caller.userId || stored.sessionId !== caller.sessionId) throw stale()

        let info: Awaited<ReturnType<typeof verifyRegistrationResponse>>['registrationInfo']
        try {
            const verification = await verifyRegistrationResponse({
                response: input.response,
                expectedChallenge: stored.challenge,
                expectedOrigin: this.config.origin,
                expectedRPID: this.config.rpId,
                requireUserVerification: true,
                supportedAlgorithmIDs: PASSKEY_ALGORITHMS,
            })
            info = verification.registrationInfo
        } catch (error) {
            this.refused('registration', caller.userId, error)
            throw rejected()
        }
        if (!info || info.credential.id !== input.response.id) throw rejected()

        const { credential } = info
        const created = await this.db.transaction(async tx => {
            const user = await lockUser(tx, caller.userId)
            if (user.status !== 'active') throw new AppError('FORBIDDEN', 'Account suspended')
            const [held] = await tx
                .select({
                    n: count(),
                })
                .from(passkeys)
                .where(eq(passkeys.userId, user.id))
            if ((held?.n ?? 0) >= this.config.maxPerUser) throw refusal('passkey', 'limit')
            const [row] = await tx
                .insert(passkeys)
                .values({
                    userId: user.id,
                    credentialId: credential.id,
                    publicKey: credential.publicKey,
                    signCount: credential.counter,
                    transports: knownTransports(credential.transports ?? []),
                    aaguid: info.aaguid,
                    rpId: this.config.rpId,
                    backupEligible: info.credentialDeviceType === 'multiDevice',
                    backedUp: info.credentialBackedUp,
                    name: input.name,
                })
                .onConflictDoNothing({
                    target: passkeys.credentialId,
                })
                .returning()
            // One credential belongs to one account, whoever tries to add it again.
            if (!row) throw refusal('passkey', 'already_registered', 'CONFLICT')
            return row
        })
        return this.toItem(created)
    }

    /** Options for a sign-in without an email: any passkey of this RP may answer. */
    async authenticationOptions(client: ClientContext) {
        if (client.ip) await this.limiter.consume(`passkey-options:${client.ip}`, 60, 600_000)
        const options = await generateAuthenticationOptions({
            rpID: this.config.rpId,
            userVerification: 'required',
            timeout: this.config.challengeTtlMs,
        })
        const challengeId = await this.challenges.put(
            'authentication',
            {
                challenge: options.challenge,
            },
            this.config.challengeTtlMs,
        )
        return {
            challengeId,
            options,
        }
    }

    async signIn(
        input: {
            challengeId: string
            response: AuthenticationResponseJSON
        },
        client: ClientContext,
    ) {
        if (client.ip) await this.limiter.consume(`passkey-ip:${client.ip}`, 30, 600_000)
        // Taken first: whatever happens next, this challenge never works again.
        const stored = await this.challenges.take('authentication', input.challengeId)
        if (!stored) throw stale()

        const { response } = input
        const [found] = await this.db
            .select()
            .from(passkeys)
            .where(and(eq(passkeys.credentialId, response.id), eq(passkeys.rpId, this.config.rpId)))
        if (!found) throw refusal('passkey', 'unknown')
        // A discoverable credential names its account: it has to be the one it was registered to.
        if (response.response.userHandle !== handleString(found.userId)) {
            this.refused('authentication', found.userId, 'user handle mismatch')
            throw rejected()
        }

        let verification: Awaited<ReturnType<typeof verifyAuthenticationResponse>>
        try {
            verification = await verifyAuthenticationResponse({
                response,
                expectedChallenge: stored.challenge,
                expectedOrigin: this.config.origin,
                expectedRPID: this.config.rpId,
                requireUserVerification: true,
                // The counter is compared below, once the signature is known to be
                // genuine, so a forged answer cannot pass for a cloned key.
                credential: {
                    id: found.credentialId,
                    publicKey: found.publicKey,
                    counter: 0,
                    transports: knownTransports(found.transports),
                },
            })
        } catch (error) {
            this.refused('authentication', found.userId, error)
            throw rejected()
        }
        if (!verification.verified) {
            this.refused('authentication', found.userId, 'bad signature')
            throw rejected()
        }

        const { newCounter, credentialBackedUp } = verification.authenticationInfo
        const outcome = await this.db.transaction(async tx => {
            const user = await lockUser(tx, found.userId)
            if (user.status !== 'active') throw new AppError('FORBIDDEN', 'Account suspended')
            // Compare-and-set: the counter has to grow, unless the device does not
            // count at all (0 before and now, as synced passkeys do).
            const [used] = await tx
                .update(passkeys)
                .set({
                    signCount: newCounter,
                    backedUp: credentialBackedUp,
                    lastUsedAt: new Date(),
                })
                .where(
                    and(
                        eq(passkeys.id, found.id),
                        or(
                            sql`${passkeys.signCount} < ${newCounter}`,
                            and(eq(passkeys.signCount, 0), sql`${newCounter} = 0`),
                        ),
                    ),
                )
                .returning({
                    id: passkeys.id,
                })
            if (!used) return null
            return {
                user,
                sessionId: await this.sessions.create(tx, user.id, client, 'passkey'),
            }
        })
        if (!outcome) {
            // A genuine signature with a counter that did not grow: most likely a copy of the key is in use.
            this.logger.warn(
                {
                    userId: found.userId,
                    passkeyId: found.id,
                    storedCounter: found.signCount,
                    presentedCounter: newCounter,
                },
                'Passkey signature counter did not grow; sign-in refused',
            )
            throw rejected()
        }
        this.relay.kick()
        const tokens = await this.sessions.issue(outcome.sessionId, outcome.user.id)
        return {
            ...tokens,
            user: this.users.toProfile(outcome.user, await this.roles.rolesOf(this.db, outcome.user.id)),
        }
    }

    /** The user's own passkeys, with the credential ids (the browser's Signal API names them). */
    async list(userId: string) {
        const rows = await this.rows(userId)
        return {
            items: rows.map(row => ({
                ...this.toItem(row),
                credentialId: row.credentialId,
            })),
        }
    }

    async remove(userId: string, passkeyId: string) {
        const removed = await this.db
            .delete(passkeys)
            .where(and(eq(passkeys.id, passkeyId), eq(passkeys.userId, userId)))
            .returning({
                id: passkeys.id,
            })
        if (removed.length === 0) throw new AppError('NOT_FOUND', 'Passkey not found')
    }

    private rows(userId: string) {
        return this.db
            .select()
            .from(passkeys)
            .where(eq(passkeys.userId, userId))
            .orderBy(asc(passkeys.createdAt), asc(passkeys.id))
    }

    private toItem(row: Passkey) {
        return {
            id: row.id,
            name: row.name,
            createdAt: row.createdAt.toISOString(),
            lastUsedAt: row.lastUsedAt?.toISOString() ?? null,
            /** Synced by its provider, so it is on the person's other devices too. */
            synced: row.backupEligible,
            /** False for a passkey of another RP: it cannot sign in here. */
            usable: row.rpId === this.config.rpId,
        }
    }

    /** The library quotes challenges in its messages; the log keeps only the kind of mismatch. */
    private refused(ceremony: 'registration' | 'authentication', userId: string, reason: unknown) {
        const message = reason instanceof Error ? reason.message : String(reason)
        this.logger.warn(
            {
                ceremony,
                userId,
                reason: /challenge/i.test(message) ? message.replace(/"[^"]*"/g, '"…"') : message.slice(0, 300),
            },
            'Passkey ceremony refused',
        )
    }
}

function knownTransports(values: readonly string[]) {
    return TRANSPORTS.filter(transport => values.includes(transport)) as AuthenticatorTransportFuture[]
}

type AuthenticatorTransportFuture = 'ble' | 'cable' | 'hybrid' | 'internal' | 'nfc' | 'smart-card' | 'usb'

/** The user row, locked for the rest of the transaction. */
async function lockUser(tx: Tx, userId: string) {
    const [user] = await tx.select().from(users).where(eq(users.id, userId)).for('update')
    if (!user) throw new AppError('NOT_FOUND', 'User not found')
    return user
}
