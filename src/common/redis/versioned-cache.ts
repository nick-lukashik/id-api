import { Inject, Injectable, Logger, Optional } from '@nestjs/common'
import type { z } from 'zod'
import { Metrics } from '../metrics/metrics.js'
import { bounded, REDIS, type RedisClient } from './redis.client.js'

export type Cached<T> = {
    value: T
    hit: boolean
}

type Operation = 'read' | 'write' | 'invalidate'

/** During an outage every request fails the same way: one warning per interval, the metric counts all. */
const WARN_INTERVAL_MS = 10_000

/**
 * Read-through cache for derived data (lists, pages). Every key of a
 * namespace embeds its current version, so `invalidate(ns)` is a single INCR
 * instead of deleting by pattern; stale keys simply expire.
 * Redis is never the source of truth: on any Redis error, a command over its
 * 500 ms budget, or an entry that fails the schema, the loader runs and the
 * request still succeeds (`cache_errors_total`). An invalidation that did not
 * reach Redis is retried (on the next use and on reconnect); until it lands,
 * that namespace is read from the database, so an outage never serves pages
 * that miss writes made during it.
 */
@Injectable()
export class VersionedCache {
    private readonly logger = new Logger('VersionedCache')
    private readonly errors
    private lastWarn = 0
    /** Namespaces whose last invalidation failed: their cached entries may be stale. */
    private readonly unflushed = new Set<string>()

    constructor(
        @Inject(REDIS) private readonly client: RedisClient,
        @Optional() metrics?: Metrics,
    ) {
        this.errors = metrics?.counter({
            name: 'cache_errors_total',
            help: 'Redis cache operations that failed or timed out (read: the cache was bypassed).',
            labelNames: [
                'operation',
            ],
        })
        client.on('ready', () => {
            for (const namespace of this.unflushed) void this.invalidate(namespace)
        })
    }

    async remember<S extends z.ZodType>(
        namespace: string,
        key: string,
        options: {
            ttlSeconds: number
            schema: S
        },
        load: () => Promise<z.output<S>>,
    ): Promise<Cached<z.output<S>>> {
        if (this.unflushed.has(namespace)) await this.invalidate(namespace)
        if (this.unflushed.has(namespace))
            return {
                value: await load(),
                hit: false,
            }
        let entryKey: string | undefined
        try {
            const version = (await bounded(this.client, this.client.get(`${namespace}:ver`))) ?? '0'
            entryKey = `${namespace}:v${version}:${key}`
            const raw = await bounded(this.client, this.client.get(entryKey))
            if (raw !== null) {
                const parsed = options.schema.safeParse(JSON.parse(raw))
                if (parsed.success)
                    return {
                        value: parsed.data,
                        hit: true,
                    }
            }
        } catch (error) {
            this.failed('read', error)
            entryKey = undefined
        }
        const value = await load()
        if (entryKey) {
            await bounded(
                this.client,
                this.client.set(entryKey, JSON.stringify(value), {
                    expiration: {
                        type: 'EX',
                        value: options.ttlSeconds,
                    },
                }),
            ).catch((error: unknown) => this.failed('write', error))
        }
        return {
            value,
            hit: false,
        }
    }

    /** Makes every entry of the namespace unreachable. */
    async invalidate(namespace: string) {
        try {
            await bounded(this.client, this.client.incr(`${namespace}:ver`))
            this.unflushed.delete(namespace)
        } catch (error) {
            this.unflushed.add(namespace)
            this.failed('invalidate', error)
        }
    }

    private failed(operation: Operation, error: unknown) {
        this.errors?.inc({
            operation,
        })
        const now = Date.now()
        if (now - this.lastWarn < WARN_INTERVAL_MS) return
        this.lastWarn = now
        this.logger.warn(
            {
                operation,
                err: (error as Error).message,
            },
            'Cache unavailable, using the database',
        )
    }
}
