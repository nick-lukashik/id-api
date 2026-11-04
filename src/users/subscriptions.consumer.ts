import { Inject, Injectable, type OnApplicationBootstrap } from '@nestjs/common'
import { subscriptionChangedV1 } from '@nick-lukashik/contracts'
import { DB } from '../common/database/database.js'
import { defineEvent, type Envelope } from '../common/messaging/event.js'
import { processOnce } from '../common/messaging/inbox.js'
import { PermanentError, RabbitMq } from '../common/messaging/rabbitmq.js'
import { defineQueue } from '../common/messaging/topology.js'
import type { Db } from '../db/types.js'
import { RolesService } from './roles.service.js'

const subscriptionChanged = defineEvent(
    subscriptionChangedV1.type,
    subscriptionChangedV1.producer,
    subscriptionChangedV1.payload,
)

export const subscriptionsQueue = defineQueue('id-api.subscriptions', [
    {
        producer: subscriptionChanged.producer,
        types: [
            subscriptionChanged.type,
        ],
    },
])

/**
 * Paid roles from subscriptions (pay-api sells none yet: the queue waits).
 * The inbox makes a redelivery a no-op; the subscription version makes an
 * event that arrives late a no-op.
 */
@Injectable()
export class SubscriptionsConsumer implements OnApplicationBootstrap {
    constructor(
        @Inject(DB) private readonly db: Db,
        private readonly rabbit: RabbitMq,
        private readonly roles: RolesService,
    ) {}

    async onApplicationBootstrap() {
        await this.rabbit.subscribe(subscriptionsQueue, async event => {
            await this.handle(event)
        })
    }

    handle(envelope: Envelope) {
        const parsed = subscriptionChanged.schema.safeParse(envelope)
        if (!parsed.success) throw new PermanentError('invalid payload')
        const event = parsed.data
        return processOnce(
            this.db,
            {
                consumer: subscriptionsQueue.name,
                eventId: event.eventId,
                type: event.type,
            },
            async tx => {
                await this.roles.applySubscription(tx, {
                    subscriptionId: event.payload.subscriptionId,
                    userId: event.payload.userId,
                    plan: event.payload.plan,
                    role: event.payload.role,
                    accessUntil: event.payload.accessUntil ? new Date(event.payload.accessUntil) : null,
                    version: event.payload.version,
                })
            },
        )
    }
}
