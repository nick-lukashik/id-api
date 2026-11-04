import { Body, Controller, Delete, Get, HttpCode, HttpStatus, Post, Req } from '@nestjs/common'
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger'
import type { AccessClaims } from '@nick-lukashik/auth'
import { Authenticated, Caller } from '@nick-lukashik/auth/nest'
import { localeSchema } from '@nick-lukashik/contracts'
import type { Request } from 'express'
import { z } from 'zod'
import { ApiErrors } from '../common/openapi/openapi.js'
import { clientContext } from '../users/client-context.js'
import { IdentitiesService } from './identities.service.js'

/** What id-web sends after Google redirected back to its callback. */
const googleCodeSchema = z.object({
    code: z.string().min(10).max(2_048),
    codeVerifier: z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/),
    nonce: z.string().min(16).max(128),
})
type GoogleCodeInput = z.infer<typeof googleCodeSchema>
const googleSignInSchema = googleCodeSchema.extend({
    locale: localeSchema.default('en'),
})
type GoogleSignIn = z.infer<typeof googleSignInSchema>

@ApiTags('sign-in')
@Controller()
export class IdentitiesController {
    constructor(private readonly identities: IdentitiesService) {}

    @Get('login/google/config')
    @ApiOperation({
        summary: 'Whether Google sign-in is on, the client id and the callback registered at Google',
    })
    config() {
        return this.identities.config()
    }

    @Post('login/google')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({
        summary: 'Exchange the Google code for a session (a new user for an unknown Google account)',
    })
    @ApiErrors(400, 403, 404, 409, 422, 429)
    signIn(
        @Body({
            schema: googleSignInSchema,
        })
        body: GoogleSignIn,
        @Req() request: Request,
    ) {
        return this.identities.signIn(body, clientContext(request))
    }

    @Get('me/identities')
    @Authenticated()
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Linked external accounts',
    })
    @ApiErrors(401)
    list(@Caller() caller: AccessClaims) {
        return this.identities.list(caller.userId)
    }

    @Post('me/identities/google')
    @HttpCode(HttpStatus.OK)
    @Authenticated()
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Link a Google account to the signed-in user',
    })
    @ApiErrors(400, 401, 403, 404, 409, 422)
    link(
        @Caller() caller: AccessClaims,
        @Body({
            schema: googleCodeSchema,
        })
        body: GoogleCodeInput,
    ) {
        return this.identities.link(caller, body)
    }

    @Delete('me/identities/google')
    @HttpCode(HttpStatus.NO_CONTENT)
    @Authenticated()
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Unlink Google; the email code still signs in',
    })
    @ApiErrors(401, 404)
    async unlink(@Caller() caller: AccessClaims) {
        await this.identities.unlink(caller.userId)
    }
}
