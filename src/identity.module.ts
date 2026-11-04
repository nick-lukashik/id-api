import { Module } from '@nestjs/common'
import { KeysModule } from './keys/keys.module.js'
import { CodeDelivery, HttpCodeDelivery } from './login/code-delivery.js'
import { LoginController } from './login/login.controller.js'
import { LoginService } from './login/login.service.js'
import { RateLimiter } from './login/rate-limiter.js'
import { RefreshStore } from './sessions/refresh-store.js'
import { SessionsService } from './sessions/sessions.service.js'
import { InternalUsersController } from './users/internal-users.controller.js'
import { MeController } from './users/me.controller.js'
import { RolesService } from './users/roles.service.js'
import { UsersService } from './users/users.service.js'

/** Users, sign-in by email code, sessions and roles. */
@Module({
    imports: [
        KeysModule,
    ],
    controllers: [
        LoginController,
        MeController,
        InternalUsersController,
    ],
    providers: [
        {
            provide: CodeDelivery,
            useClass: HttpCodeDelivery,
        },
        LoginService,
        RateLimiter,
        RefreshStore,
        SessionsService,
        RolesService,
        UsersService,
    ],
    exports: [
        RolesService,
    ],
})
export class IdentityModule {}
