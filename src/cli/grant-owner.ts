import 'reflect-metadata'
import { NestFactory } from '@nestjs/core'

/**
 * The first owner: `node dist/cli/grant-owner.js <email>` in a pod of id-api
 * (kubectl exec), after that person has signed in once. Idempotent.
 */
const email = process.argv[2]
if (!email?.includes('@')) {
    process.stderr.write('usage: node dist/cli/grant-owner.js <email>\n')
    process.exit(2)
}
// Runs next to the live server in its pod: no metrics listener of its own, or its
// port is taken (EADDRINUSE). Set before the modules read the environment.
process.env.METRICS_PORT = '0'
const { AppModule } = await import('../app.module.js')
const { RolesService } = await import('../users/roles.service.js')
const app = await NestFactory.createApplicationContext(AppModule, {
    logger: [
        'error',
    ],
})
try {
    const result = await app.get(RolesService).grant(email, 'owner', 'cli', 'first owner from the command line')
    process.stdout.write(`${JSON.stringify(result)}\n`)
} finally {
    await app.close()
}
