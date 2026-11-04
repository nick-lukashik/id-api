import { Module } from '@nestjs/common'
import { googleProvider } from './identities/google.provider.js'
import { IdentitiesController } from './identities/identities.controller.js'
import { IdentitiesService } from './identities/identities.service.js'
import { KeysModule } from './keys/keys.module.js'
import { CodeDelivery, HttpCodeDelivery } from './login/code-delivery.js'
import { LoginController } from './login/login.controller.js'
import { LoginService } from './login/login.service.js'
import { RateLimiter } from './login/rate-limiter.js'
import { OAuthController } from './oauth/oauth.controller.js'
import { OAuthService } from './oauth/oauth.service.js'
import { ChallengeStore } from './passkeys/challenge-store.js'
import { PasskeysController } from './passkeys/passkeys.controller.js'
import { PasskeysService } from './passkeys/passkeys.service.js'
import { RefreshStore } from './sessions/refresh-store.js'
import { SessionsService } from './sessions/sessions.service.js'
import { GrantsService } from './users/grants.service.js'
import { InternalUsersController } from './users/internal-users.controller.js'
import { MeController } from './users/me.controller.js'
import { RolesService } from './users/roles.service.js'
import { SubscriptionsConsumer } from './users/subscriptions.consumer.js'
import { UsersService } from './users/users.service.js'

/** Users, sign-in (email code, Google, passkeys), sessions, sign-in of the other apps, and roles. */
@Module({
    imports: [
        KeysModule,
    ],
    controllers: [
        LoginController,
        IdentitiesController,
        PasskeysController,
        OAuthController,
        MeController,
        InternalUsersController,
    ],
    providers: [
        {
            provide: CodeDelivery,
            useClass: HttpCodeDelivery,
        },
        googleProvider,
        LoginService,
        IdentitiesService,
        ChallengeStore,
        PasskeysService,
        OAuthService,
        RateLimiter,
        RefreshStore,
        SessionsService,
        RolesService,
        GrantsService,
        UsersService,
        SubscriptionsConsumer,
    ],
    exports: [
        RolesService,
    ],
})
export class IdentityModule {}
