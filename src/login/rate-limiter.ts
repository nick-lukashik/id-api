import { randomUUID } from 'node:crypto'
import { Inject, Injectable, Logger, type OnModuleInit, Optional } from '@nestjs/common'
import { Counter } from '@prometheus-io/client'
import { HealthRegistry } from '../common/health/health.registry.js'
import { AppError } from '../common/http/app-error.js'
import { Metrics } from '../common/metrics/metrics.js'
import { bounded, REDIS, type RedisClient } from '../common/redis/redis.client.js'

/** The counter the alert RateLimitFailingOpen watches (same name and help as the throttler storage). */
const UNCHECKED_METRIC = 'rate_limit_fail_open_total'
const UNCHECKED_HELP = 'Requests let through without a rate-limit check because Redis was unavailable.'
/** Lifetime of the readiness probe's key. */
const PROBE_TTL_MS = 10_000

/**
 * Fixed-window limits of the sign-in flow. With Redis down, slow or refusing
 * writes they refuse (503, logged with the limit, counted): an unchecked limit
 * would let anyone send codes to any address and spread guesses over any
 * number of challenges.
 */
@Injectable()
export class RateLimiter implements OnModuleInit {
    private readonly logger = new Logger('RateLimiter')
    /** One key per process, so replicas probe independently. */
    private readonly probeKey = `health:limits:${randomUUID()}`
    private unchecked: Counter | undefined

    constructor(
        @Inject(REDIS) private readonly redis: RedisClient,
        private readonly health: HealthRegistry,
        @Optional() private readonly metrics?: Metrics,
    ) {}

    onModuleInit() {
        // A name is registered once per registry, and RedisThrottlerStorage (src/common)
        // registers this one, without labels, in its constructor; every constructor has
        // run by now. Which limit failed goes to the log.
        const registered = this.metrics?.registry.getSingleMetric(UNCHECKED_METRIC)
        this.unchecked =
            registered instanceof Counter
                ? registered
                : this.metrics?.counter({
                      name: UNCHECKED_METRIC,
                      help: UNCHECKED_HELP,
                  })
        // Required: PING still answers when `noeviction` makes Redis refuse every write,
        // so only a write read back shows that the limits can work.
        this.health.register('rate-limits', () => this.probe())
    }

    async consume(key: string, limit: number, windowMs: number) {
        let reply: readonly number[]
        try {
            reply = await bounded(this.redis, this.redis.consumeRate(`limit:${key}`, windowMs, limit, 0))
        } catch (error) {
            this.unchecked?.inc()
            this.logger.warn(
                {
                    key: key.split(':')[0],
                    err: (error as Error).message,
                },
                'Rate limiter unavailable, refusing',
            )
            throw new AppError('UNAVAILABLE', 'Sign-in is unavailable right now, retry later', undefined, {
                cause: error,
            })
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

    private async probe() {
        const value = randomUUID()
        await bounded(
            this.redis,
            this.redis.set(this.probeKey, value, {
                expiration: {
                    type: 'PX',
                    value: PROBE_TTL_MS,
                },
            }),
        )
        if ((await bounded(this.redis, this.redis.get(this.probeKey))) !== value)
            throw new Error('Redis did not keep a write')
    }
}
