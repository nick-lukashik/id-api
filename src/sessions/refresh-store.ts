import { createHash, randomBytes } from 'node:crypto'
import { Inject, Injectable, type OnModuleInit } from '@nestjs/common'
import { HealthRegistry } from '../common/health/health.registry.js'
import { bounded, REDIS, type RedisClient } from '../common/redis/redis.client.js'

/**
 * Refresh-token rotation in one atomic Lua script.
 *
 * Per session: `rt:<sid>` holds sha256(current token), TTL = refresh lifetime;
 * `rtg:<sid>` holds "<sha256(previous)>:<current plaintext>" for the grace window;
 * `rtp:<sid>` holds sha256 of every superseded token, scored by when it was
 * superseded, for the refresh lifetime (older ones would have expired anyway).
 *
 * Presented token:
 * - == current                → OK: rotate, keep a grace entry for the old token;
 * - == previous within grace  → RETRY: the token already issued (two tabs, a lost response);
 * - superseded, family alive  → REUSE: all keys deleted, the session is burned;
 * - anything else             → DEAD: revoked, expired or never issued; nothing changes,
 *                               so a session id alone (the `sid` claim) burns nothing.
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
  redis.call('ZADD', KEYS[3], ARGV[6], ARGV[1])
  redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', '(' .. ARGV[7])
  redis.call('EXPIRE', KEYS[3], ARGV[5])
  return { 'OK', ARGV[3] }
end
local grace = redis.call('GET', KEYS[2])
if grace then
  local sep = string.find(grace, ':', 1, true)
  if string.sub(grace, 1, sep - 1) == ARGV[1] then
    return { 'RETRY', string.sub(grace, sep + 1) }
  end
end
local superseded = redis.call('ZSCORE', KEYS[3], ARGV[1])
if superseded and tonumber(superseded) >= tonumber(ARGV[7]) then
  redis.call('DEL', KEYS[1], KEYS[2], KEYS[3])
  return { 'REUSE' }
end
return { 'DEAD' }
`

/** 1 when the token is the current one or the previous one within grace (same keys as ROTATE). */
const HOLDS = `
local cur = redis.call('HGET', KEYS[1], 'cur')
if not cur then return 0 end
if cur == ARGV[1] then return 1 end
local grace = redis.call('GET', KEYS[2])
if grace and string.sub(grace, 1, string.find(grace, ':', 1, true) - 1) == ARGV[1] then return 1 end
return 0
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
        const sessionId = familyOf(presented)
        if (!sessionId)
            return {
                result: 'DEAD',
                sessionId: null,
            }
        const next = mint(sessionId)
        const now = Date.now()
        const reply = (await bounded(
            this.redis,
            this.redis.eval(ROTATE, {
                keys: [
                    key(sessionId),
                    graceKey(sessionId),
                    supersededKey(sessionId),
                ],
                arguments: [
                    hash(presented),
                    hash(next),
                    next,
                    String(options.graceMs),
                    String(options.ttlSec),
                    String(now),
                    String(now - options.ttlSec * 1_000),
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

    /**
     * The session the token still opens (the current one, or the previous one
     * within grace), or null: signing out takes the token, not just its id.
     */
    async sessionOf(presented: string): Promise<string | null> {
        const sessionId = familyOf(presented)
        if (!sessionId) return null
        const held = await bounded(
            this.redis,
            this.redis.eval(HOLDS, {
                keys: [
                    key(sessionId),
                    graceKey(sessionId),
                ],
                arguments: [
                    hash(presented),
                ],
            }),
        )
        return held === 1 ? sessionId : null
    }

    async revoke(sessionIds: string[]) {
        if (sessionIds.length === 0) return
        await bounded(
            this.redis,
            this.redis.del(
                sessionIds.flatMap(sid => [
                    key(sid),
                    graceKey(sid),
                    supersededKey(sid),
                ]),
            ),
        )
    }
}

const key = (sid: string) => `rt:${sid}`
const graceKey = (sid: string) => `rtg:${sid}`
const supersededKey = (sid: string) => `rtp:${sid}`
/** The session id a well-formed token starts with, or null. */
const familyOf = (token: string) => {
    const sessionId = token.split('.')[0] ?? ''
    return SESSION_ID.test(sessionId) && token.length <= 200 ? sessionId : null
}
/** `<sid>.<256 random bits>`: the prefix finds the family without storing the token. */
const mint = (sid: string) => `${sid}.${randomBytes(32).toString('base64url')}`
const hash = (token: string) => createHash('sha256').update(token).digest('hex')
