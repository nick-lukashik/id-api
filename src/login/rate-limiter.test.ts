import { Logger } from '@nestjs/common'
import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from 'vitest'
import { Metrics } from '../common/metrics/metrics.js'
import { RateLimiter } from './rate-limiter.js'

describe('RateLimiter without Redis', () => {
    let warn: MockInstance<Logger['warn']>
    let metrics: Metrics
    let limiter: RateLimiter

    beforeEach(() => {
        vi.useFakeTimers({
            now: new Date('2026-11-05T00:00:00.000Z'),
        })
        warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => {})
        metrics = new Metrics({
            service: 'id-api',
            version: 'test',
            port: 0,
        })
        limiter = new RateLimiter(
            {
                consumeRate: () => Promise.reject(new Error('The client is closed')),
            } as never,
            {
                register: () => {},
            } as never,
            metrics,
        )
        limiter.onModuleInit()
    })
    afterEach(() => {
        vi.useRealTimers()
    })

    const refused = () =>
        expect(limiter.consume('ip:203.0.113.7', 20, 3_600_000)).rejects.toMatchObject({
            code: 'UNAVAILABLE',
        })
    const counted = async () => {
        const metric = metrics.registry.getSingleMetric('rate_limit_fail_open_total')
        if (!metric) throw new Error('no metric rate_limit_fail_open_total')
        return (await metric.get()).values.reduce((sum, value) => sum + value.value, 0)
    }

    it('refuses and counts every request, and warns once per 10 seconds', async () => {
        await refused()
        await refused()
        await vi.advanceTimersByTimeAsync(9_999)
        await refused()
        expect(warn).toHaveBeenCalledTimes(1)
        expect(await counted()).toBe(3)

        await vi.advanceTimersByTimeAsync(1)
        await refused()
        expect(warn).toHaveBeenCalledTimes(2)
        expect(await counted()).toBe(4)
    })

    it('names the limit in the warning, never the address behind it', async () => {
        await refused()
        expect(warn).toHaveBeenCalledWith(
            {
                key: 'ip',
                err: 'The client is closed',
            },
            'Rate limiter unavailable, refusing',
        )
    })
})
