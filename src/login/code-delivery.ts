import { Inject, Injectable, Logger } from '@nestjs/common'
import type { ConfigType } from '@nestjs/config'
import type { Locale } from '@nick-lukashik/contracts'
import { Metrics } from '../common/metrics/metrics.js'
import { internalConfig } from '../config/config.js'

export type CodeMessage = {
    challengeId: string
    email: string
    code: string
    locale: Locale
    expiresAt: string
}

export type DeliveryStatus = 'accepted' | 'failed'

/** How the code reaches the person; tests swap it for a recorder. */
export abstract class CodeDelivery {
    abstract deliver(message: CodeMessage): Promise<DeliveryStatus>
}

/**
 * A synchronous call to notifications-api inside the cluster: the code never
 * enters the broker, the outbox, a table or a log, and cannot be delivered
 * after it expires (notifications-api checks `expiresAt`).
 */
@Injectable()
export class HttpCodeDelivery extends CodeDelivery {
    private readonly logger = new Logger('CodeDelivery')
    private readonly deliveries

    constructor(
        @Inject(internalConfig.KEY) private readonly config: ConfigType<typeof internalConfig>,
        metrics: Metrics,
    ) {
        super()
        this.deliveries = metrics.counter({
            name: 'auth_code_deliveries_total',
            help: 'Sign-in codes handed to notifications-api, by result (unreachable: no answer or not 2xx).',
            labelNames: [
                'result',
            ],
        })
    }

    async deliver(message: CodeMessage): Promise<DeliveryStatus> {
        const result = await this.post(message)
        this.deliveries.inc({
            result,
        })
        return result === 'accepted' ? 'accepted' : 'failed'
    }

    private async post(message: CodeMessage): Promise<DeliveryStatus | 'unreachable'> {
        let response: Response
        try {
            // NOTIFICATIONS_URL is the bare origin; notifications-api serves under the global prefix `api`.
            response = await fetch(`${this.config.notificationsUrl}/api/v1/internal/auth-codes`, {
                method: 'POST',
                headers: {
                    authorization: `Bearer ${this.config.notificationsToken}`,
                    'content-type': 'application/json',
                },
                body: JSON.stringify(message),
                signal: AbortSignal.timeout(8_000),
            })
            if (!response.ok) throw new Error(`notifications-api answered ${response.status}`)
        } catch (error) {
            this.failed(message, error)
            return 'unreachable'
        }
        try {
            const body = (await response.json()) as {
                status?: unknown
            }
            return body.status === 'accepted' ? 'accepted' : 'failed'
        } catch (error) {
            this.failed(message, error)
            return 'failed'
        }
    }

    private failed(message: CodeMessage, error: unknown) {
        this.logger.warn(
            {
                challengeId: message.challengeId,
                err: (error as Error).message,
            },
            'Sign-in code delivery failed',
        )
    }
}
