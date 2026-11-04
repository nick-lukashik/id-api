import { randomBytes, randomUUID } from 'node:crypto'
import { createServer, type Server } from 'node:http'
import { Logger } from '@nestjs/common'
import { afterAll, beforeAll, beforeEach, describe, expect, it, type MockInstance, vi } from 'vitest'
import { Metrics } from '../src/common/metrics/metrics.js'
import { type CodeMessage, HttpCodeDelivery } from '../src/login/code-delivery.js'

const TOKEN = randomBytes(32).toString('hex')

type Received = {
    contentType: string | undefined
    body: unknown
}

const listen = async (server: Server) => {
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const address = server.address()
    if (!address || typeof address === 'string') throw new Error('no address')
    return `http://127.0.0.1:${address.port}`
}

/**
 * A stand-in for notifications-api: only `POST /api/v1/internal/auth-codes`
 * (its global prefix `api`, version 1) with the service token, answering
 * `answer`; any other route is 404, as Nest answers it.
 */
async function startNotifications() {
    const received: Received[] = []
    const stub = {
        received,
        answer: {
            status: 200,
            body: {
                status: 'accepted',
            } as unknown,
        },
        url: '',
        close: () => new Promise<void>(resolve => server.close(() => resolve())),
    }
    const server = createServer(async (request, response) => {
        const send = (status: number, body?: unknown) => {
            response.statusCode = status
            response.setHeader('content-type', 'application/json')
            response.end(body === undefined ? undefined : JSON.stringify(body))
        }
        if (request.method !== 'POST' || request.url !== '/api/v1/internal/auth-codes')
            return send(404, {
                code: 'NOT_FOUND',
            })
        if (request.headers.authorization !== `Bearer ${TOKEN}`) return send(401)
        const chunks: Buffer[] = []
        for await (const chunk of request) chunks.push(chunk as Buffer)
        received.push({
            contentType: request.headers['content-type'],
            body: JSON.parse(Buffer.concat(chunks).toString('utf8')),
        })
        send(stub.answer.status, stub.answer.body)
    })
    stub.url = await listen(server)
    return stub
}

/** An origin nothing listens on: a port taken and released again. */
async function closedOrigin() {
    const server = createServer()
    const url = await listen(server)
    await new Promise<void>(resolve => server.close(() => resolve()))
    return url
}

const message = (): CodeMessage => ({
    challengeId: randomUUID(),
    email: 'anna@example.com',
    code: '482913',
    locale: 'ru',
    expiresAt: new Date(Date.now() + 600_000).toISOString(),
})

let notifications: Awaited<ReturnType<typeof startNotifications>>
let metrics: Metrics
let warn: MockInstance<Logger['warn']>

beforeAll(async () => {
    notifications = await startNotifications()
})
afterAll(async () => {
    await notifications?.close()
})
beforeEach(() => {
    notifications.received.length = 0
    notifications.answer = {
        status: 200,
        body: {
            status: 'accepted',
        },
    }
    metrics = new Metrics({
        service: 'id-api',
        version: 'test',
        port: 0,
    })
    warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => {})
})

/** HttpCodeDelivery against `notificationsUrl` (a bare origin, as NOTIFICATIONS_URL). */
const delivery = (notificationsUrl = notifications.url) =>
    new HttpCodeDelivery(
        {
            notificationsUrl,
            notificationsToken: TOKEN,
            token: randomBytes(32).toString('hex'),
        },
        metrics,
    )

/** `auth_code_deliveries_total` of one `result` (0 when the series does not exist). */
const deliveries = async (result: string) => {
    const metric = metrics.registry.getSingleMetric('auth_code_deliveries_total')
    if (!metric) throw new Error('no metric auth_code_deliveries_total')
    const { values } = await metric.get()
    return values.filter(value => value.labels.result === result).reduce((sum, value) => sum + value.value, 0)
}

describe('HttpCodeDelivery', () => {
    it('has a series at 0 for every result from the start, so a first failure is an increase', async () => {
        delivery()
        const metric = metrics.registry.getSingleMetric('auth_code_deliveries_total')
        if (!metric) throw new Error('no metric auth_code_deliveries_total')
        const { values } = await metric.get()
        expect(
            values
                .map(value => ({
                    result: value.labels.result,
                    value: value.value,
                }))
                .sort((a, b) => String(a.result).localeCompare(String(b.result))),
        ).toEqual([
            {
                result: 'accepted',
                value: 0,
            },
            {
                result: 'failed',
                value: 0,
            },
            {
                result: 'unreachable',
                value: 0,
            },
        ])
    })

    it('posts the code to notifications-api under /api/v1 with the service token', async () => {
        const sent = message()
        await expect(delivery().deliver(sent)).resolves.toBe('accepted')
        expect(notifications.received).toEqual([
            {
                contentType: 'application/json',
                body: sent,
            },
        ])
        expect(await deliveries('accepted')).toBe(1)
        expect(await deliveries('failed')).toBe(0)
        expect(await deliveries('unreachable')).toBe(0)
    })

    it('is failed when notifications-api could not send the email', async () => {
        notifications.answer = {
            status: 200,
            body: {
                status: 'failed',
            },
        }
        await expect(delivery().deliver(message())).resolves.toBe('failed')
        expect(notifications.received).toHaveLength(1)
        expect(await deliveries('failed')).toBe(1)
        expect(await deliveries('unreachable')).toBe(0)
    })

    it('is failed, and counted unreachable, on a route that does not exist (404)', async () => {
        // NOTIFICATIONS_URL with a path: the prefix twice.
        await expect(delivery(`${notifications.url}/api`).deliver(message())).resolves.toBe('failed')
        expect(notifications.received).toHaveLength(0)
        expect(await deliveries('unreachable')).toBe(1)
        expect(await deliveries('failed')).toBe(0)
    })

    it('is failed, and counted unreachable, on an error of notifications-api', async () => {
        notifications.answer = {
            status: 503,
            body: {
                code: 'UNAVAILABLE',
            },
        }
        await expect(delivery().deliver(message())).resolves.toBe('failed')
        expect(await deliveries('unreachable')).toBe(1)
        expect(await deliveries('failed')).toBe(0)
    })

    it('is failed, and counted unreachable, when notifications-api does not answer', async () => {
        const sent = message()
        await expect(delivery(await closedOrigin()).deliver(sent)).resolves.toBe('failed')
        expect(await deliveries('unreachable')).toBe(1)
        // The warning names the challenge, never the code or the address.
        const logged = JSON.stringify(warn.mock.calls)
        expect(logged).toContain(sent.challengeId)
        expect(logged).not.toContain(sent.code)
        expect(logged).not.toContain(sent.email)
    })
})
