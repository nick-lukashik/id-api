import { Module } from '@nestjs/common'
import { Retention } from './retention.js'

/** Deletes sign-in data past the retention periods the privacy policy quotes. */
@Module({
    providers: [
        Retention,
    ],
})
export class RetentionModule {}
