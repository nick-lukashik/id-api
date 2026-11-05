import { parseArgs } from 'node:util'
import { z } from 'zod'
import { defineEnv, rabbitEnvSchema } from '../common/config/define-env.js'
import { replayDeadLetters } from '../common/messaging/replay.js'
import { SERVICE_NAME } from '../config/config.js'

// Moves dead letters back to their queue after the cause was fixed:
//   node dist/messaging/replay-dlq.js <queue> [--limit N]
// e.g. kubectl exec deploy/id-api -- node dist/messaging/replay-dlq.js id-api.subscriptions --limit 100
// Of the app's config it reads only RABBITMQ_URL. Exit code 1: nothing or only part was replayed.

const log = (level: 'info' | 'error', msg: string, fields: Record<string, unknown>) =>
    console.log(
        JSON.stringify({
            level,
            time: new Date().toISOString(),
            msg,
            ...fields,
        }),
    )

const argsSchema = z.object({
    queue: z.string().min(1).max(255),
    limit: z.coerce.number().int().min(1).optional(),
})

try {
    const { positionals, values } = parseArgs({
        allowPositionals: true,
        options: {
            limit: {
                type: 'string',
            },
        },
    })
    const args = argsSchema.parse({
        queue: positionals[0],
        limit: values.limit,
    })
    const env = defineEnv(rabbitEnvSchema)
    const result = await replayDeadLetters(env().RABBITMQ_URL, args.queue, {
        limit: args.limit,
        connectionName: `${SERVICE_NAME}-replay-dlq`,
    })
    log('info', 'dead letters replayed', result)
} catch (error) {
    log('error', 'dead letter replay failed', {
        err: error instanceof z.ZodError ? 'usage: replay-dlq <queue> [--limit N]' : (error as Error).message,
    })
    process.exitCode = 1
}
