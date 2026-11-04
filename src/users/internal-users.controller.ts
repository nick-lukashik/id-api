import { Controller, Get, Inject, Param, ParseUUIDPipe } from '@nestjs/common'
import { ApiExcludeController } from '@nestjs/swagger'
import { Internal } from '@nick-lukashik/auth/nest'
import { DB } from '../common/database/database.js'
import type { Db } from '../db/types.js'
import { UsersService } from './users.service.js'

/** In-cluster callers with this service's token: notifications-api reads where to send. */
@ApiExcludeController()
@Controller('internal/users')
@Internal()
export class InternalUsersController {
    constructor(
        private readonly users: UsersService,
        @Inject(DB) private readonly db: Db,
    ) {}

    @Get(':id')
    async get(@Param('id', new ParseUUIDPipe()) id: string) {
        const user = await this.users.get(this.db, id)
        return {
            id: user.id,
            email: user.email,
            locale: user.locale,
            displayName: user.displayName,
            status: user.status,
        }
    }
}
