import { Logger } from '@nestjs/common'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Retention } from './retention.js'

const START = new Date('2026-11-04T00:00:00.000Z')

describe('Retention schedule', () => {
    afterEach(() => {
        vi.useRealTimers()
    })

    function started() {
        vi.useFakeTimers({
            now: START,
        })
        const retention = new Retention(
            {} as never,
            {
                refreshTtlSec: 2_592_000,
            } as never,
        )
        return retention
    }

    it('runs a pass a minute after start, then every hour, and none after shutdown', async () => {
        const retention = started()
        const purge = vi.spyOn(retention, 'purge').mockResolvedValue(null)
        retention.onApplicationBootstrap()

        await vi.advanceTimersByTimeAsync(59_999)
        expect(purge).not.toHaveBeenCalled()
        await vi.advanceTimersByTimeAsync(1)
        expect(purge).toHaveBeenCalledTimes(1)
        expect(purge.mock.calls[0]?.[0]).toEqual(new Date(START.getTime() + 60_000))
        await vi.advanceTimersByTimeAsync(3_600_000)
        expect(purge).toHaveBeenCalledTimes(2)

        await retention.beforeApplicationShutdown()
        await vi.advanceTimersByTimeAsync(10 * 3_600_000)
        expect(purge).toHaveBeenCalledTimes(2)
    })

    it('keeps the schedule after a failed pass', async () => {
        const retention = started()
        const logged = vi.spyOn(Logger.prototype, 'error').mockImplementation(() => {})
        const purge = vi
            .spyOn(retention, 'purge')
            .mockRejectedValueOnce(new Error('connection refused'))
            .mockResolvedValue(null)
        retention.onApplicationBootstrap()

        await vi.advanceTimersByTimeAsync(60_000)
        expect(logged).toHaveBeenCalledTimes(1)
        await vi.advanceTimersByTimeAsync(3_600_000)
        expect(purge).toHaveBeenCalledTimes(2)
        await retention.beforeApplicationShutdown()
    })

    it('waits for a running pass on shutdown', async () => {
        const retention = started()
        let finish = () => {}
        vi.spyOn(retention, 'purge').mockImplementation(
            () =>
                new Promise(resolve => {
                    finish = () => resolve(null)
                }),
        )
        retention.onApplicationBootstrap()
        await vi.advanceTimersByTimeAsync(60_000)

        let stopped = false
        const stopping = retention.beforeApplicationShutdown().then(() => {
            stopped = true
        })
        await vi.advanceTimersByTimeAsync(0)
        expect(stopped).toBe(false)
        finish()
        await stopping
        expect(stopped).toBe(true)
    })
})
