import { Controller, Get, Header, VERSION_NEUTRAL } from '@nestjs/common'
import { ApiOperation, ApiTags } from '@nestjs/swagger'
import { SigningKeys } from './signing-keys.js'

@ApiTags('keys')
/** Outside /api and versions: verifiers expect the standard path. */
@Controller({
    version: VERSION_NEUTRAL,
})
export class JwksController {
    constructor(private readonly keys: SigningKeys) {}

    @Get('.well-known/jwks.json')
    @Header('Cache-Control', 'public, max-age=300')
    @ApiOperation({
        summary: 'Public keys of access tokens (ES256), current and still accepted',
    })
    jwks() {
        return this.keys.jwks()
    }
}
