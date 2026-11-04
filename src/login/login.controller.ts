import { Body, Controller, HttpCode, HttpStatus, Post, Req } from '@nestjs/common'
import { ApiOperation, ApiTags } from '@nestjs/swagger'
import type { Request } from 'express'
import { ApiErrors } from '../common/openapi/openapi.js'
import { SessionsService } from '../sessions/sessions.service.js'
import { clientContext } from '../users/client-context.js'
import {
    type RefreshInput,
    type RequestCode,
    refreshSchema,
    requestCodeSchema,
    type VerifyCode,
    verifyCodeSchema,
} from './login.schemas.js'
import { LoginService } from './login.service.js'

/** Called by id-web on the server; the browser never holds these tokens. */
@ApiTags('sign-in')
@Controller()
export class LoginController {
    constructor(
        private readonly login: LoginService,
        private readonly sessions: SessionsService,
    ) {}

    @Post('login/email')
    @HttpCode(HttpStatus.ACCEPTED)
    @ApiOperation({
        summary: 'Send a 6-digit sign-in code; the same answer whether or not the account exists',
    })
    @ApiErrors(400, 429)
    requestCode(
        @Body({
            schema: requestCodeSchema,
        })
        body: RequestCode,
        @Req() request: Request,
    ) {
        return this.login.requestCode(body.email, body.locale, clientContext(request))
    }

    @Post('login/email/verify')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({
        summary: 'Exchange the code for a session: access and refresh tokens',
    })
    @ApiErrors(400, 403, 422, 429)
    verify(
        @Body({
            schema: verifyCodeSchema,
        })
        body: VerifyCode,
        @Req() request: Request,
    ) {
        return this.login.verify(body.challengeId, body.code, clientContext(request))
    }

    @Post('sessions/refresh')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({
        summary: 'Rotate the refresh token; a reused one ends the session',
    })
    @ApiErrors(400, 401)
    refresh(
        @Body({
            schema: refreshSchema,
        })
        body: RefreshInput,
    ) {
        return this.sessions.rotate(body.refreshToken)
    }

    @Post('sessions/logout')
    @HttpCode(HttpStatus.NO_CONTENT)
    @ApiOperation({
        summary: 'End the session of this refresh token',
    })
    @ApiErrors(400)
    async logout(
        @Body({
            schema: refreshSchema,
        })
        body: RefreshInput,
    ) {
        await this.sessions.logout(body.refreshToken)
    }
}
