import { Body, Controller, Delete, Get, HttpCode, HttpStatus, Param, ParseUUIDPipe, Post, Req } from '@nestjs/common'
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger'
import type { AccessClaims } from '@nick-lukashik/auth'
import { Authenticated, Caller } from '@nick-lukashik/auth/nest'
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server'
import type { Request } from 'express'
import { z } from 'zod'
import { ApiErrors } from '../common/openapi/openapi.js'
import { clientContext } from '../users/client-context.js'
import { PasskeysService } from './passkeys.service.js'

/** A shape check before the library checks everything that matters. */
const credentialSchema = z.looseObject({
    id: z.string().min(1).max(1_400),
    rawId: z.string().min(1).max(1_400),
    type: z.literal('public-key'),
    response: z.looseObject({
        clientDataJSON: z.string().max(4_096),
    }),
    clientExtensionResults: z.looseObject({}).default({}),
})

const signInSchema = z.object({
    challengeId: z.uuid(),
    response: credentialSchema,
})
const registerSchema = z.object({
    challengeId: z.uuid(),
    name: z.string().trim().min(1).max(60),
    response: credentialSchema,
})

@ApiTags('passkeys')
@Controller()
export class PasskeysController {
    constructor(private readonly passkeys: PasskeysService) {}

    @Post('login/passkey/options')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({
        summary: 'A one-time challenge for signing in with any passkey of this site',
    })
    @ApiErrors(429)
    options(@Req() request: Request) {
        return this.passkeys.authenticationOptions(clientContext(request))
    }

    @Post('login/passkey/verify')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({
        summary: "Check the browser's answer and open a session",
    })
    @ApiErrors(400, 403, 422, 429)
    signIn(
        @Body({
            schema: signInSchema,
        })
        body: z.infer<typeof signInSchema>,
        @Req() request: Request,
    ) {
        return this.passkeys.signIn(
            {
                challengeId: body.challengeId,
                response: body.response as unknown as AuthenticationResponseJSON,
            },
            clientContext(request),
        )
    }

    @Get('me/passkeys')
    @Authenticated()
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Your passkeys',
    })
    @ApiErrors(401)
    list(@Caller() caller: AccessClaims) {
        return this.passkeys.list(caller.userId)
    }

    @Post('me/passkeys/options')
    @HttpCode(HttpStatus.OK)
    @Authenticated()
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Creation options for a new passkey; needs a recent sign-in',
    })
    @ApiErrors(401, 403, 422, 429)
    registrationOptions(@Caller() caller: AccessClaims) {
        return this.passkeys.registrationOptions(caller)
    }

    @Post('me/passkeys')
    @Authenticated()
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Save the new passkey the browser created',
    })
    @ApiErrors(400, 401, 403, 409, 422)
    register(
        @Caller() caller: AccessClaims,
        @Body({
            schema: registerSchema,
        })
        body: z.infer<typeof registerSchema>,
    ) {
        return this.passkeys.register(caller, {
            challengeId: body.challengeId,
            name: body.name,
            response: body.response as unknown as RegistrationResponseJSON,
        })
    }

    @Delete('me/passkeys/:id')
    @HttpCode(HttpStatus.NO_CONTENT)
    @Authenticated()
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Remove a passkey; the email code still signs in',
    })
    @ApiErrors(401, 404)
    async remove(@Caller() caller: AccessClaims, @Param('id', new ParseUUIDPipe()) id: string) {
        await this.passkeys.remove(caller.userId, id)
    }
}
