import {
    type DynamicModule,
    Global,
    Inject,
    Injectable,
    type InjectionToken,
    Logger,
    Module,
    type OnApplicationShutdown,
    type OnModuleInit,
    Optional,
} from '@nestjs/common'
import { HealthRegistry } from '../health/health.registry.js'
import { Metrics } from '../metrics/metrics.js'
import { bounded, createRedisClient, REDIS, type RedisClient, type RedisOptions } from './redis.client.js'
import { RedisThrottlerStorage } from './redis-throttler.storage.js'
import { VersionedCache } from './versioned-cache.js'

/** How long startup waits for Redis before going on without it (cache bypassed, limiter open). */
const STARTUP_WAIT_MS = 3_000
const CLOSE_TIMEOUT_MS = 1_000

const sleep = <T>(ms: number, value: T) =>
    new Promise<T>(resolve => {
        setTimeout(() => resolve(value), ms).unref()
    })

@Injectable()
class RedisLifecycle implements OnModuleInit, OnApplicationShutdown {
    constructor(
        @Inject(REDIS) private readonly client: RedisClient,
        private readonly health: HealthRegistry,
        @Optional() metrics?: Metrics,
    ) {
        metrics?.gauge({
            name: 'redis_up',
            help: '1 while the Redis client is connected; 0 while the cache is bypassed and the rate limiter is open.',
            collect() {
                this.set(client.isReady ? 1 : 0)
            },
        })
    }

    onModuleInit() {
        // Degradable: reported in the readiness body, never a 503.
        this.health.register(
            'redis',
            async () => {
                await bounded(this.client, this.client.ping())
            },
            {
                required: false,
            },
        )
    }

    async onApplicationShutdown() {
        if (!this.client.isOpen) return
        // close() waits for pending replies, which never come from a hung server.
        const closed =
            this.client.isReady
            && (await Promise.race([
                this.client.close().then(() => true),
                sleep(CLOSE_TIMEOUT_MS, false),
            ]))
        if (!closed) this.client.destroy()
    }
}

/** The Redis client (`@Inject(REDIS)`), the throttler storage and the list cache. */
@Global()
@Module({})
export class RedisModule {
    static forRootAsync(options: {
        inject?: InjectionToken[]
        useFactory: (...args: never[]) => RedisOptions
    }): DynamicModule {
        const logger = new Logger('Redis')
        return {
            module: RedisModule,
            providers: [
                {
                    provide: REDIS,
                    inject: options.inject ?? [],
                    useFactory: async (...args: never[]) => {
                        const client = createRedisClient(options.useFactory(...args))
                        // Without a listener a connection error would crash the process.
                        client.on('error', (error: Error) =>
                            logger.warn(
                                {
                                    err: error.message,
                                },
                                'Redis connection error',
                            ),
                        )
                        // Keeps reconnecting in the background; only the wait at startup is bounded.
                        const connected = client.connect().then(
                            () => true,
                            () => false,
                        )
                        if (
                            !(await Promise.race([
                                connected,
                                sleep(STARTUP_WAIT_MS, false),
                            ]))
                        ) {
                            logger.warn(
                                {
                                    waitedMs: STARTUP_WAIT_MS,
                                },
                                'Redis unavailable at startup; starting without it (cache bypassed, rate limiter open)',
                            )
                        }
                        return client
                    },
                },
                RedisLifecycle,
                RedisThrottlerStorage,
                VersionedCache,
            ],
            exports: [
                REDIS,
                RedisThrottlerStorage,
                VersionedCache,
            ],
        }
    }
}
