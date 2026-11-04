import { Module } from '@nestjs/common'
import type { ConfigType } from '@nestjs/config'
import { AuthModule, InternalAuthModule } from '@nick-lukashik/auth/nest'
import { DatabaseModule } from './common/database/database.module.js'
import { HealthModule } from './common/health/health.module.js'
import { createLoggerModule } from './common/logging/logger.module.js'
import { MessagingModule } from './common/messaging/messaging.module.js'
import { eventsExchange } from './common/messaging/topology.js'
import { MetricsModule } from './common/metrics/metrics.module.js'
import { RedisModule } from './common/redis/redis.module.js'
import { appConfig, dbConfig, internalConfig, rabbitConfig, redisConfig, tokenConfig } from './config/config.js'
import { AppConfigModule } from './config/config.module.js'
import * as schema from './db/schema.js'
import { IdentityModule } from './identity.module.js'
import { KeysModule } from './keys/keys.module.js'
import { SigningKeys } from './keys/signing-keys.js'
import { userRegistered } from './users/users.service.js'

type App = ConfigType<typeof appConfig>

@Module({
    imports: [
        AppConfigModule,
        createLoggerModule({
            inject: [
                appConfig.KEY,
            ],
            useFactory: (app: App) => ({
                service: app.service,
                version: app.version,
                level: app.logLevel,
            }),
        }),
        HealthModule.forRootAsync({
            inject: [
                appConfig.KEY,
            ],
            useFactory: (app: App) => ({
                shutdownDelayMs: app.shutdownDelayMs,
            }),
        }),
        MetricsModule.forRootAsync({
            inject: [
                appConfig.KEY,
            ],
            useFactory: (app: App) => ({
                service: app.service,
                version: app.version,
                port: app.metricsPort,
            }),
        }),
        DatabaseModule.forRootAsync({
            schema,
            inject: [
                dbConfig.KEY,
                appConfig.KEY,
            ],
            useFactory: (db: ConfigType<typeof dbConfig>, app: App) => ({
                url: db.url,
                max: db.max,
                applicationName: app.service,
            }),
        }),
        RedisModule.forRootAsync({
            inject: [
                redisConfig.KEY,
                appConfig.KEY,
            ],
            useFactory: (redis: ConfigType<typeof redisConfig>, app: App) => ({
                url: redis.url,
                name: app.service,
                keyPrefix: `${app.service}:`,
            }),
        }),
        MessagingModule.forRootAsync({
            inject: [
                rabbitConfig.KEY,
                appConfig.KEY,
            ],
            useFactory: (rabbit: ConfigType<typeof rabbitConfig>, app: App) => ({
                url: rabbit.url,
                connectionName: app.service,
                exchanges: [
                    eventsExchange(userRegistered.producer),
                ],
            }),
        }),
        // id-api verifies its own tokens with the local keys, no HTTP.
        AuthModule.forRootAsync({
            imports: [
                KeysModule,
            ],
            inject: [
                SigningKeys,
                tokenConfig.KEY,
            ],
            useFactory: (keys: SigningKeys, token: ConfigType<typeof tokenConfig>) => ({
                keys: keys.verificationKeys,
                issuer: token.issuer,
                audience: token.audience,
            }),
        }),
        InternalAuthModule.forRootAsync({
            inject: [
                internalConfig.KEY,
            ],
            useFactory: (internal: ConfigType<typeof internalConfig>) => internal.token,
        }),
        IdentityModule,
    ],
})
export class AppModule {}
