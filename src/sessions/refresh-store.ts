import { createHash, randomBytes } from 'node:crypto'
import { Inject, Injectable, Logger, type OnModuleInit } from '@nestjs/common'
import { HealthRegistry } from '../common/health/health.registry.js'
import { AppError } from '../common/http/app-error.js'
import { bounded, REDIS, type RedisClient } from '../common/redis/redis.client.js'

/**
 * Superseded hashes kept per session. Redis runs `noeviction`: with a 5-minute
 * access token and a 30-day refresh token a session in constant use would
 * otherwise collect about 8640 of them. 512 are about 42 hours of such use.
 */
const SUPERSEDED_KEPT = 512

/**
 * Refresh-token rotation in one atomic Lua script.
 *
 * Per session: `rt:<sid>` holds `cur`, sha256(current token), and `prev`, sha256 of the
 * token that was current before it, TTL = refresh lifetime; `rtg:<sid>` holds
 * "<sha256(previous)>:<current plaintext>" for the grace window; `rtp:<sid>` holds sha256
 * of the newest SUPERSEDED_KEPT superseded tokens, scored by when each was superseded,
 * for the refresh lifetime (older ones would have expired anyway).
 *
 * Presented token:
 * - == current                → OK: rotate, keep a grace entry for the old token;
 * - == previous within grace  → RETRY: the token already issued (two tabs, parallel requests);
 * - == previous after grace   → REISSUED: a new token in place of the current one. Any use
 *                               of the current one would have turned it, so it was never
 *                               used: its answer got lost (a closed tab, no network);
 * - superseded, family alive  → REUSE: all keys deleted, the session is burned;
 * - anything else             → DEAD: revoked, expired or never issued; nothing changes,
 *                               so a session id alone (the `sid` claim) burns nothing.
 *
 * A token older than the cap counts as DEAD, not REUSE: replaying one that old
 * is refused but no longer burns the session.
 *
 * Whoever holds the previous token gets a session while the person is away, and when
 * the person comes back with the token replaced here, that is REUSE and both are out.
 *
 * The grace entry keeps the current plaintext for at most the grace window
 * inside Redis of the cluster; it is never logged.
 */
const ROTATE = `
local function turn(from)
  redis.call('HSET', KEYS[1], 'cur', ARGV[2])
  redis.call('EXPIRE', KEYS[1], ARGV[5])
  if tonumber(ARGV[4]) > 0 then
    redis.call('SET', KEYS[2], ARGV[1] .. ':' .. ARGV[3], 'PX', ARGV[4])
  end
  redis.call('ZADD', KEYS[3], ARGV[6], from)
  redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', '(' .. ARGV[7])
  redis.call('ZREMRANGEBYRANK', KEYS[3], 0, ${-SUPERSEDED_KEPT - 1})
  redis.call('EXPIRE', KEYS[3], ARGV[5])
end
local cur = redis.call('HGET', KEYS[1], 'cur')
if not cur then return { 'DEAD' } end
if cur == ARGV[1] then
  redis.call('HSET', KEYS[1], 'prev', ARGV[1])
  turn(ARGV[1])
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
  if redis.call('HGET', KEYS[1], 'prev') == ARGV[1] then
    turn(cur)
    return { 'REISSUED', ARGV[3] }
  end
  redis.call('DEL', KEYS[1], KEYS[2], KEYS[3])
  return { 'REUSE' }
end
return { 'DEAD' }
`

/**
 * 1 when the token is one this live session was really given: the current one, the
 * previous one within grace, or a superseded one (same keys as ROTATE). A sign-out with an
 * old token may ask for what a refresh with it would do anyway, which is to end the session.
 */
const WAS_ISSUED = `
local cur = redis.call('HGET', KEYS[1], 'cur')
if not cur then return 0 end
if cur == ARGV[1] then return 1 end
local grace = redis.call('GET', KEYS[2])
if grace and string.sub(grace, 1, string.find(grace, ':', 1, true) - 1) == ARGV[1] then return 1 end
if redis.call('ZSCORE', KEYS[3], ARGV[1]) then return 1 end
return 0
`

export type RotateResult =
    | {
          result: 'OK' | 'RETRY' | 'REISSUED'
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
    private readonly logger = new Logger('RefreshStore')

    constructor(
        @Inject(REDIS) private readonly redis: RedisClient,
        private readonly health: HealthRegistry,
    ) {}

    onModuleInit() {
        this.health.register('sessions', async () => {
            await bounded(this.redis, this.redis.ping())
        })
    }

    /** A command of this store: without Redis no session can be refreshed or ended, and that is a 503. */
    private async available<T>(command: () => Promise<T>) {
        try {
            return await bounded(this.redis, command())
        } catch (error) {
            this.logger.warn(
                {
                    err: error,
                },
                'Redis unavailable for a session',
            )
            throw new AppError('UNAVAILABLE', 'Sessions are unavailable, retry')
        }
    }

    private async twice<T>(command: () => Promise<T>) {
        try {
            return await bounded(this.redis, command())
        } catch {
            return this.available(command)
        }
    }

    /** Starts a session's refresh family and returns its first token. */
    async issue(sessionId: string, ttlSec: number) {
        const token = mint(sessionId)
        await this.available(() =>
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
        // Once more on a failure: if Redis did turn the token and only the reply was lost,
        // the same request now finds it in its grace window and gets the token issued.
        const turn = () =>
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
            })
        const reply = (await this.twice(turn)) as [
            'OK' | 'RETRY' | 'REISSUED' | 'REUSE' | 'DEAD',
            string | undefined,
        ]
        const [result, token] = reply
        if ((result === 'OK' || result === 'RETRY' || result === 'REISSUED') && token)
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

    /** Whether the session can still be refreshed: ending one deletes its key. */
    async isLive(sessionId: string) {
        return (await this.available(() => this.redis.exists(key(sessionId)))) === 1
    }

    /** The live session the token was really given by, or null: signing out takes the token, not just its id. */
    async sessionOf(presented: string): Promise<string | null> {
        const sessionId = familyOf(presented)
        if (!sessionId) return null
        const held = await this.available(() =>
            this.redis.eval(WAS_ISSUED, {
                keys: [
                    key(sessionId),
                    graceKey(sessionId),
                    supersededKey(sessionId),
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
        await this.available(() =>
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
export const familyOf = (token: string) => {
    const sessionId = token.split('.')[0] ?? ''
    return SESSION_ID.test(sessionId) && token.length <= 200 ? sessionId : null
}
/** `<sid>.<256 random bits>`: the prefix finds the family without storing the token. */
const mint = (sid: string) => `${sid}.${randomBytes(32).toString('base64url')}`
const hash = (token: string) => createHash('sha256').update(token).digest('hex')
