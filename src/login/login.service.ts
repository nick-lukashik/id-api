import { createHash, createHmac, randomInt, randomUUID, timingSafeEqual } from 'node:crypto'
import { Inject, Injectable } from '@nestjs/common'
import type { ConfigType } from '@nestjs/config'
import type { Locale } from '@nick-lukashik/contracts'
import { and, eq, gt, isNull, lt, sql } from 'drizzle-orm'
import { DB } from '../common/database/database.js'
import { AppError } from '../common/http/app-error.js'
import { OutboxRelay } from '../common/messaging/outbox-relay.js'
import { loginConfig } from '../config/config.js'
import { loginChallenges } from '../db/schema.js'
import type { Db } from '../db/types.js'
import { SessionsService } from '../sessions/sessions.service.js'
import type { ClientContext } from '../users/client-context.js'
import { RolesService } from '../users/roles.service.js'
import { UsersService } from '../users/users.service.js'
import { CodeDelivery } from './code-delivery.js'
import { RateLimiter } from './rate-limiter.js'

const digest = (value: string) => createHash('sha256').update(value).digest('hex')

@Injectable()
export class LoginService {
    constructor(
        @Inject(DB) private readonly db: Db,
        @Inject(loginConfig.KEY) private readonly config: ConfigType<typeof loginConfig>,
        private readonly delivery: CodeDelivery,
        private readonly limiter: RateLimiter,
        private readonly users: UsersService,
        private readonly roles: RolesService,
        private readonly sessions: SessionsService,
        private readonly relay: OutboxRelay,
    ) {}

    /** Step 1. The same answer whether or not the account exists. */
    async requestCode(rawEmail: string, locale: Locale, client: ClientContext) {
        const email = rawEmail.trim().toLowerCase()
        await this.limiter.consume(`resend:${digest(email)}`, 1, this.config.resendCooldownMs)
        await this.limiter.consume(`email-day:${digest(email)}`, 10, 24 * 3_600_000)
        if (client.ip) await this.limiter.consume(`ip:${client.ip}`, 20, 3_600_000)

        const now = new Date()
        const expiresAt = new Date(now.getTime() + this.config.codeTtlSec * 1000)
        const code = randomInt(0, 1_000_000).toString().padStart(6, '0')
        const challengeId = randomUUID()
        await this.db.insert(loginChallenges).values({
            id: challengeId,
            email,
            codeHash: this.hash(challengeId, code),
            locale,
            expiresAt,
            createdAt: now,
        })
        const status = await this.delivery.deliver({
            challengeId,
            email,
            code,
            locale,
            expiresAt: expiresAt.toISOString(),
        })
        await this.db
            .update(loginChallenges)
            .set({
                deliveryStatus: status,
            })
            .where(eq(loginChallenges.id, challengeId))
        return {
            challengeId,
            expiresAt: expiresAt.toISOString(),
            resendAfter: new Date(now.getTime() + this.config.resendCooldownMs).toISOString(),
            deliveryStatus: status,
        }
    }

    /** Step 2. A code works once, before it expires, within its attempt budget. */
    async verify(challengeId: string, code: string, client: ClientContext) {
        if (client.ip) await this.limiter.consume(`verify-ip:${client.ip}`, 30, 600_000)
        const now = new Date()
        const [challenge] = await this.db.select().from(loginChallenges).where(eq(loginChallenges.id, challengeId))
        if (!challenge || challenge.consumedAt) throw invalid('invalid_code')
        if (challenge.expiresAt <= now) throw invalid('expired')
        if (challenge.attempts >= this.config.maxAttempts) throw invalid('too_many_attempts')

        const expected = Buffer.from(challenge.codeHash, 'hex')
        const actual = Buffer.from(this.hash(challengeId, code), 'hex')
        if (!timingSafeEqual(expected, actual)) {
            const [row] = await this.db
                .update(loginChallenges)
                .set({
                    attempts: sql`${loginChallenges.attempts} + 1`,
                })
                .where(and(eq(loginChallenges.id, challengeId), isNull(loginChallenges.consumedAt)))
                .returning({
                    attempts: loginChallenges.attempts,
                })
            throw invalid((row?.attempts ?? 0) >= this.config.maxAttempts ? 'too_many_attempts' : 'invalid_code')
        }

        // Atomic consume: of two concurrent correct verifications only one wins.
        const { user, sessionId } = await this.db.transaction(async tx => {
            const [consumed] = await tx
                .update(loginChallenges)
                .set({
                    consumedAt: now,
                })
                .where(
                    and(
                        eq(loginChallenges.id, challengeId),
                        isNull(loginChallenges.consumedAt),
                        gt(loginChallenges.expiresAt, now),
                        lt(loginChallenges.attempts, this.config.maxAttempts),
                    ),
                )
                .returning({
                    email: loginChallenges.email,
                    locale: loginChallenges.locale,
                })
            if (!consumed) throw invalid('invalid_code')
            const found = await this.users.findOrCreate(tx, consumed.email, consumed.locale)
            if (found.status !== 'active') throw new AppError('FORBIDDEN', 'Account suspended')
            return {
                user: found,
                sessionId: await this.sessions.create(tx, found.id, client),
            }
        })
        this.relay.kick()
        const tokens = await this.sessions.issue(sessionId, user.id)
        return {
            ...tokens,
            user: this.users.toProfile(user, await this.roles.rolesOf(this.db, user.id)),
        }
    }

    private hash(challengeId: string, code: string) {
        return createHmac('sha256', this.config.pepper).update(`${challengeId}:${code}`).digest('hex')
    }
}

const invalid = (reason: 'invalid_code' | 'expired' | 'too_many_attempts') =>
    new AppError('UNPROCESSABLE', 'Sign-in code not accepted', [
        {
            path: 'code',
            message: reason,
        },
    ])
