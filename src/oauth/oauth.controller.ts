import { Body, Controller, Get, HttpCode, HttpStatus, Param, Post, Query, Req } from '@nestjs/common'
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger'
import type { AccessClaims } from '@nick-lukashik/auth'
import { Authenticated, Caller } from '@nick-lukashik/auth/nest'
import type { Request } from 'express'
import { z } from 'zod'
import { AppError } from '../common/http/app-error.js'
import { ApiErrors } from '../common/openapi/openapi.js'
import { clientContext } from '../users/client-context.js'
import { OAuthService } from './oauth.service.js'

const clientId = z.string().regex(/^[a-z][a-z0-9-]{2,40}$/)
const redirectUri = z.url().max(500)
// RFC 7636: an S256 challenge is base64url(sha256(verifier)), 43 characters.
const challenge = z.string().regex(/^[A-Za-z0-9_-]{43}$/)

const clientQuerySchema = z.object({
    redirectUri,
})
const authorizeSchema = z.object({
    clientId,
    redirectUri,
    codeChallenge: challenge,
    codeChallengeMethod: z.literal('S256'),
})
const tokenSchema = z.object({
    grantType: z.literal('authorization_code'),
    clientId,
    redirectUri,
    code: z.string().min(40).max(60),
    codeVerifier: z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/),
})

@ApiTags('apps')
@Controller('oauth')
export class OAuthController {
    constructor(private readonly oauth: OAuthService) {}

    @Get('clients/:id')
    @ApiOperation({
        summary: 'Whether an app and its callback are registered (id-web asks before it signs anyone in)',
    })
    @ApiErrors(404, 422)
    client(
        @Param('id') id: string,
        @Query({
            schema: clientQuerySchema,
        })
        query: z.infer<typeof clientQuerySchema>,
    ) {
        if (!clientId.safeParse(id).success) throw new AppError('NOT_FOUND', 'Unknown app')
        return this.oauth.client(id, query.redirectUri)
    }

    @Post('authorize')
    @HttpCode(HttpStatus.OK)
    @Authenticated()
    @ApiBearerAuth()
    @ApiOperation({
        summary: 'A 60-second code for the signed-in user (called by id-web)',
    })
    @ApiErrors(400, 401, 422)
    authorize(
        @Caller() caller: AccessClaims,
        @Body({
            schema: authorizeSchema,
        })
        body: z.infer<typeof authorizeSchema>,
    ) {
        return this.oauth.authorize(caller.userId, body)
    }

    @Post('token')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({
        summary: "The code for the app's own session (called by the app's server)",
    })
    @ApiErrors(400, 422, 429)
    token(
        @Body({
            schema: tokenSchema,
        })
        body: z.infer<typeof tokenSchema>,
        @Req() request: Request,
    ) {
        return this.oauth.exchange(body, clientContext(request))
    }
}
