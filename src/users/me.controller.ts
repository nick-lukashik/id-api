import {
    Body,
    Controller,
    Delete,
    Get,
    HttpCode,
    HttpStatus,
    Param,
    ParseUUIDPipe,
    Patch,
    Post,
    Query,
} from '@nestjs/common'
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger'
import type { AccessClaims } from '@nick-lukashik/auth'
import { Authenticated, Caller } from '@nick-lukashik/auth/nest'
import { z } from 'zod'
import { ApiErrors } from '../common/openapi/openapi.js'
import { type UpdateProfile, updateProfileSchema } from '../login/login.schemas.js'
import { SessionsService } from '../sessions/sessions.service.js'
import { UsersService } from './users.service.js'

const sessionsQuerySchema = z.object({
    /** Opaque: `nextCursor` of the previous page. */
    cursor: z.string().min(1).max(200).optional(),
})

/** The caller's own account. */
@ApiTags('me')
@ApiBearerAuth()
@Controller('me')
@Authenticated()
export class MeController {
    constructor(
        private readonly users: UsersService,
        private readonly sessions: SessionsService,
    ) {}

    @Get()
    @ApiOperation({
        summary:
            'Profile, roles and whether the session of this access token is still alive: one call for a page of a site. `active` is null when that cannot be told',
    })
    @ApiErrors(401)
    async me(@Caller() caller: AccessClaims) {
        const [profile, active] = await Promise.all([
            this.users.profile(caller.userId),
            this.sessions.isLive(caller.sessionId).catch(() => null),
        ])
        return {
            ...profile,
            active,
        }
    }

    @Patch()
    @ApiOperation({
        summary: 'Change the display name or the language',
    })
    @ApiErrors(400, 401)
    update(
        @Caller() caller: AccessClaims,
        @Body({
            schema: updateProfileSchema,
        })
        body: UpdateProfile,
    ) {
        return this.users.update(caller.userId, body)
    }

    @Get('sessions')
    @ApiOperation({
        summary:
            'Active sessions, the current one and the sites signed in from it marked; most recently active first, 50 to a page',
    })
    @ApiErrors(400, 401)
    async listSessions(
        @Caller() caller: AccessClaims,
        @Query({
            schema: sessionsQuerySchema,
        })
        query: z.infer<typeof sessionsQuerySchema>,
    ) {
        const page = await this.sessions.list(caller.userId, query.cursor)
        return {
            items: page.items.map(row => ({
                id: row.id,
                createdAt: row.createdAt.toISOString(),
                lastActiveAt: row.lastActiveAt.toISOString(),
                userAgent: row.userAgent,
                ip: row.ip,
                authMethod: row.authMethod,
                clientId: row.clientId,
                current: row.id === caller.sessionId,
                thisBrowser: row.parentSessionId === caller.sessionId,
            })),
            nextCursor: page.nextCursor,
        }
    }

    @Get('session')
    @ApiOperation({
        summary:
            'Whether the session of this access token is still alive; the token alone stays valid until it expires',
    })
    @ApiErrors(401)
    async session(@Caller() caller: AccessClaims) {
        return {
            active: await this.sessions.isLive(caller.sessionId),
        }
    }

    @Delete('sessions/:id')
    @HttpCode(HttpStatus.NO_CONTENT)
    @ApiOperation({
        summary: 'End one of your sessions',
    })
    @ApiErrors(401, 404)
    async revoke(@Caller() caller: AccessClaims, @Param('id', new ParseUUIDPipe()) id: string) {
        await this.sessions.revokeOwn(caller.userId, id)
    }

    @Post('sessions/revoke-others')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({
        summary: 'End every session but this one',
    })
    @ApiErrors(401)
    async revokeOthers(@Caller() caller: AccessClaims) {
        return {
            revoked: await this.sessions.revokeOthers(caller.userId, caller.sessionId),
        }
    }
}
