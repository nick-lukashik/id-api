import { createHash, randomBytes } from 'node:crypto'
import { Inject, Injectable, type OnModuleInit } from '@nestjs/common'
import { HealthRegistry } from '../common/health/health.registry.js'
import { bounded, REDIS, type RedisClient } from '../common/redis/redis.client.js'

/**
 * Refresh-token rotation in one atomic Lua script.
 *
 * Per session: `rt:<sid>` holds sha256(current token), TTL = refresh lifetime;
 * `rtg:<sid>` holds "<sha256(previous)>:<current plaintext>" for the grace window.
 *
 * Presented token:
 * - == current                → OK: rotate, keep a grace entry for the old token;
 * - == previous within grace  → RETRY: the token already issued (two tabs, a lost response);
 * - anything else, alive      → REUSE: both keys deleted, the session is burned;
 * - no `rt:<sid>`             → DEAD: revoked or expired.
 *
 * The grace entry keeps the current plaintext for at most the grace window
 * inside Redis of the cluster; it is never logged.
 */
const ROTATE = `
local cur = redis.call('HGET', KEYS[1], 'cur')
if not cur then return { 'DEAD' } end
if cur == ARGV[1] then
  redis.call('HSET', KEYS[1], 'cur', ARGV[2])
  redis.call('EXPIRE', KEYS[1], ARGV[5])
  if tonumber(ARGV[4]) > 0 then
    redis.call('SET', KEYS[2], ARGV[1] .. ':' .. ARGV[3], 'PX', ARGV[4])
  end
  return { 'OK', ARGV[3] }
end
local grace = redis.call('GET', KEYS[2])
if grace then
  local sep = string.find(grace, ':', 1, true)
  if string.sub(grace, 1, sep - 1) == ARGV[1] then
    return { 'RETRY', string.sub(grace, sep + 1) }
  end
end
redis.call('DEL', KEYS[1], KEYS[2])
return { 'REUSE' }
`

export type RotateResult =
    | {
          result: 'OK' | 'RETRY'
          sessionId: string
          token: string
      }
    | {
          result: 'REUSE' | 'DEAD'
          sessionId: string | null
      }

const SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

/**
 * Redis is required here, unlike the cache of other services: without it no
 * session can be refreshed, so readiness fails and the error is a 503.
 */
@Injectable()
export class RefreshStore implements OnModuleInit {
    constructor(
        @Inject(REDIS) private readonly redis: RedisClient,
        private readonly health: HealthRegistry,
    ) {}

    onModuleInit() {
        this.health.register('sessions', async () => {
            await bounded(this.redis, this.redis.ping())
        })
    }

    /** Starts a session's refresh family and returns its first token. */
    async issue(sessionId: string, ttlSec: number) {
        const token = mint(sessionId)
        await bounded(
            this.redis,
            this.redis.multi().hSet(key(sessionId), 'cur', hash(token)).expire(key(sessionId), ttlSec).exec(),
        )
        return token
    }

    async rotate(
        presented: string,
        options: {
            ttlSec: number
            graceMs: number
        },
    ): Promise<RotateResult> {
        const sessionId = presented.split('.')[0] ?? ''
        if (!SESSION_ID.test(sessionId) || presented.length > 200)
            return {
                result: 'DEAD',
                sessionId: null,
            }
        const next = mint(sessionId)
        const reply = (await bounded(
            this.redis,
            this.redis.eval(ROTATE, {
                keys: [
                    key(sessionId),
                    graceKey(sessionId),
                ],
                arguments: [
                    hash(presented),
                    hash(next),
                    next,
                    String(options.graceMs),
                    String(options.ttlSec),
                ],
            }),
        )) as [
            'OK' | 'RETRY' | 'REUSE' | 'DEAD',
            string | undefined,
        ]
        const [result, token] = reply
        if ((result === 'OK' || result === 'RETRY') && token)
            return {
                result,
                sessionId,
                token,
            }
        return {
            result: result === 'REUSE' ? 'REUSE' : 'DEAD',
            sessionId,
        }
    }

    async revoke(sessionIds: string[]) {
        if (sessionIds.length === 0) return
        await bounded(
            this.redis,
            this.redis.del(
                sessionIds.flatMap(sid => [
                    key(sid),
                    graceKey(sid),
                ]),
            ),
        )
    }
}

const key = (sid: string) => `rt:${sid}`
const graceKey = (sid: string) => `rtg:${sid}`
/** `<sid>.<256 random bits>`: the prefix finds the family without storing the token. */
const mint = (sid: string) => `${sid}.${randomBytes(32).toString('base64url')}`
const hash = (token: string) => createHash('sha256').update(token).digest('hex')
