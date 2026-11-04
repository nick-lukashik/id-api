import { type CommandParser, createClient, defineScript } from '@redis/client'

/**
 * Fixed-window counter with an optional block, in one atomic step.
 * KEYS: hits, block. ARGV: windowMs, limit, blockMs.
 * Returns: hits, windowTtlMs, blocked (0/1), blockTtlMs.
 */
const CONSUME_RATE = `
local blockTtl = redis.call('PTTL', KEYS[2])
if blockTtl > 0 then
  return { tonumber(redis.call('GET', KEYS[1]) or '0'), redis.call('PTTL', KEYS[1]), 1, blockTtl }
end
local hits = redis.call('INCR', KEYS[1])
if hits == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
local ttl = redis.call('PTTL', KEYS[1])
if hits > tonumber(ARGV[2]) and tonumber(ARGV[3]) > 0 then
  redis.call('SET', KEYS[2], '1', 'PX', ARGV[3])
  return { hits, ttl, 1, tonumber(ARGV[3]) }
end
return { hits, ttl, 0, 0 }
`

export type RateReply = [
    hits: number,
    ttlMs: number,
    blocked: 0 | 1,
    blockMs: number,
]

const consumeRate = defineScript({
    NUMBER_OF_KEYS: 2,
    SCRIPT: CONSUME_RATE,
    parseCommand(parser: CommandParser, key: string, windowMs: number, limit: number, blockMs: number) {
        parser.pushKey(`${key}:hits`)
        parser.pushKey(`${key}:block`)
        parser.push(String(windowMs), String(limit), String(blockMs))
    },
    transformReply: (reply: unknown) => reply as RateReply,
})

export type RedisOptions = {
    url: string
    /** Client name shown in `CLIENT LIST`. */
    name: string
    /** Prepended to every key: the instance may be shared by several services. */
    keyPrefix: string
}

/** The budget of one Redis command (service contract). */
export const REDIS_COMMAND_TIMEOUT_MS = 500

export class RedisTimeoutError extends Error {
    override name = 'RedisTimeoutError'
}

const generations = new WeakMap<RedisClient, number>()

/** Bounds reply wait and discards the stuck connection without replaying commands. */
export async function bounded<T>(client: RedisClient, command: Promise<T>, ms = REDIS_COMMAND_TIMEOUT_MS): Promise<T> {
    const generation = generations.get(client) ?? 0
    let timer: NodeJS.Timeout | undefined
    try {
        return await Promise.race([
            command,
            new Promise<never>((_, reject) => {
                timer = setTimeout(() => {
                    reject(new RedisTimeoutError(`Redis command exceeded ${ms} ms`))
                    // Other commands on this connection may time out in the same tick.
                    // Never reset their replacement connection or reconnect during shutdown.
                    if (client.isOpen && client.isReady && (generations.get(client) ?? 0) === generation) {
                        generations.set(client, generation + 1)
                        client.destroy()
                        void client.connect().catch(() => {})
                    }
                }, ms)
            }),
        ])
    } finally {
        clearTimeout(timer)
    }
}

/**
 * One long-lived client per process. Commands fail fast while disconnected
 * (no offline queue): a cache falls back to the database, and a non-idempotent
 * INCR is never replayed after a reconnect. Redis is degradable, so the
 * client reconnects forever, also when it was never connected.
 */
export function createRedisClient(options: RedisOptions) {
    return createClient({
        url: options.url,
        name: options.name,
        keyPrefix: options.keyPrefix,
        disableOfflineQueue: true,
        commandsQueueMaxLength: 256,
        pingInterval: 2_000,
        commandOptions: {
            timeout: REDIS_COMMAND_TIMEOUT_MS,
        },
        socket: {
            connectTimeout: 2_000,
            socketTimeout: 5_000,
            reconnectStrategy: retries => Math.min(100 * 2 ** retries, 5_000),
        },
        scripts: {
            consumeRate,
        },
    })
}

export type RedisClient = ReturnType<typeof createRedisClient>

/** Injection token of the shared client: `@Inject(REDIS) redis: RedisClient`. */
export const REDIS = Symbol('REDIS')
