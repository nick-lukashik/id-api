import { randomUUID } from 'node:crypto'
import { Inject, Injectable } from '@nestjs/common'
import { z } from 'zod'
import { AppError } from '../common/http/app-error.js'
import { bounded, REDIS, type RedisClient } from '../common/redis/redis.client.js'

export type Ceremony = 'registration' | 'authentication'

const storedSchema = z.object({
    challenge: z.string().min(16),
    /** Registration only: whose ceremony it is, and from which session. */
    userId: z.uuid().optional(),
    sessionId: z.uuid().optional(),
})
export type StoredChallenge = z.infer<typeof storedSchema>

const ID = /^[0-9a-f-]{36}$/

/**
 * One-time WebAuthn challenges in Redis. The browser holds only an opaque
 * id; the challenge, and for a registration its user and session, stay here
 * with a TTL. `take` is one GETDEL: of two verifications racing with one id
 * only one gets the challenge, a used or expired id gets nothing.
 */
@Injectable()
export class ChallengeStore {
    constructor(@Inject(REDIS) private readonly redis: RedisClient) {}

    async put(ceremony: Ceremony, value: StoredChallenge, ttlMs: number) {
        const id = randomUUID()
        try {
            await bounded(
                this.redis,
                this.redis.set(keyOf(ceremony, id), JSON.stringify(value), {
                    expiration: {
                        type: 'PX',
                        value: ttlMs,
                    },
                }),
            )
        } catch {
            throw new AppError('UNAVAILABLE', 'Passkeys are unavailable right now')
        }
        return id
    }

    /** The challenge, once; null when unknown, expired or already taken. */
    async take(ceremony: Ceremony, id: string): Promise<StoredChallenge | null> {
        if (!ID.test(id)) return null
        let raw: string | null
        try {
            raw = await bounded(this.redis, this.redis.getDel(keyOf(ceremony, id)))
        } catch {
            throw new AppError('UNAVAILABLE', 'Passkeys are unavailable right now')
        }
        if (!raw) return null
        try {
            const parsed = storedSchema.safeParse(JSON.parse(raw))
            return parsed.success ? parsed.data : null
        } catch {
            return null
        }
    }
}

const keyOf = (ceremony: Ceremony, id: string) => `webauthn:${ceremony === 'registration' ? 'reg' : 'auth'}:${id}`
