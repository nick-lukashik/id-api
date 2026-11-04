import { Inject, Injectable, Logger } from '@nestjs/common'
import { AppError } from '../common/http/app-error.js'
import { bounded, REDIS, type RedisClient } from '../common/redis/redis.client.js'

/**
 * Fixed-window limits of the sign-in flow. With Redis down they open (logged):
 * the attempt budget of each code lives in Postgres and still holds.
 */
@Injectable()
export class RateLimiter {
    private readonly logger = new Logger('RateLimiter')

    constructor(@Inject(REDIS) private readonly redis: RedisClient) {}

    async consume(key: string, limit: number, windowMs: number) {
        let reply: readonly number[]
        try {
            reply = await bounded(this.redis, this.redis.consumeRate(`limit:${key}`, windowMs, limit, 0))
        } catch (error) {
            this.logger.warn(
                {
                    key: key.split(':')[0],
                    err: (error as Error).message,
                },
                'Rate limiter unavailable, open',
            )
            return
        }
        const [hits = 0, ttlMs = 0] = reply
        if (hits > limit) {
            throw new AppError('RATE_LIMITED', 'Too many attempts, retry later', [
                {
                    path: 'retryAfterMs',
                    message: String(Math.max(ttlMs, 0)),
                },
            ])
        }
    }
}
