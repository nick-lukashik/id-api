import { Inject, Injectable, Logger, Optional } from '@nestjs/common'
import type { ThrottlerStorage } from '@nestjs/throttler'
import { Metrics } from '../metrics/metrics.js'
import { bounded, type RateReply, REDIS, type RedisClient } from './redis.client.js'

type ThrottlerStorageRecord = Awaited<ReturnType<ThrottlerStorage['increment']>>

const WARN_INTERVAL_MS = 10_000

/**
 * @nestjs/throttler storage in Redis: limits are shared by every replica and
 * survive restarts. `ttl` and `blockDuration` arrive in ms; the record is in seconds.
 * Fails open: when Redis is down or over its 500 ms budget the request is
 * allowed, logged and counted (`rate_limit_fail_open_total`), because the
 * limiter must not take the API down with it.
 */
@Injectable()
export class RedisThrottlerStorage implements ThrottlerStorage {
    private readonly logger = new Logger('RateLimit')
    private readonly failOpen
    private lastWarn = 0

    constructor(
        @Inject(REDIS) private readonly client: RedisClient,
        @Optional() metrics?: Metrics,
    ) {
        this.failOpen = metrics?.counter({
            name: 'rate_limit_fail_open_total',
            help: 'Requests let through without a rate-limit check because Redis was unavailable.',
        })
    }

    async increment(
        key: string,
        ttl: number,
        limit: number,
        blockDuration: number,
        throttlerName: string,
    ): Promise<ThrottlerStorageRecord> {
        let reply: RateReply
        try {
            reply = (await bounded(
                this.client,
                this.client.consumeRate(
                    `rate:${throttlerName}:${key}`,
                    ttl,
                    limit,
                    blockDuration > 0 ? blockDuration : ttl,
                ),
            )) as RateReply
        } catch (error) {
            this.opened(error)
            return {
                totalHits: 0,
                timeToExpire: Math.ceil(ttl / 1000),
                isBlocked: false,
                timeToBlockExpire: 0,
            }
        }
        const [hits, ttlMs, blocked, blockMs] = reply
        return {
            totalHits: hits,
            timeToExpire: Math.max(0, Math.ceil(ttlMs / 1000)),
            isBlocked: blocked === 1 || hits > limit,
            timeToBlockExpire: Math.max(0, Math.ceil(blockMs / 1000)),
        }
    }

    private opened(error: unknown) {
        this.failOpen?.inc()
        const now = Date.now()
        if (now - this.lastWarn < WARN_INTERVAL_MS) return
        this.lastWarn = now
        this.logger.warn(
            {
                err: (error as Error).message,
            },
            'Rate limiter unavailable, allowing requests',
        )
    }
}
