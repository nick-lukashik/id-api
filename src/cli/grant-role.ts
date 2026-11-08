import 'reflect-metadata'
import { NestFactory } from '@nestjs/core'
import { isRole } from '@nick-lukashik/auth'

/**
 * A role for a person who signed in once: `node dist/cli/grant-role.js <email> <role>`
 * in a pod of id-api (kubectl exec). Product roles such as `tailor` open a
 * service; the first owner keeps grant-owner.js. Idempotent; the person's next
 * access token (at most 5 minutes) carries the role.
 */
const [email, role] = process.argv.slice(2)
if (!email?.includes('@') || !isRole(role)) {
    process.stderr.write('usage: node dist/cli/grant-role.js <email> <role>  (a role of @nick-lukashik/auth)\n')
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
    const result = await app.get(RolesService).grant(email, role, 'cli', `role ${role} from the command line`)
    process.stdout.write(`${JSON.stringify(result)}\n`)
} finally {
    await app.close()
}
