import { Inject, Injectable } from '@nestjs/common'
import { type Locale, userRegisteredV1 } from '@nick-lukashik/contracts'
import { eq } from 'drizzle-orm'
import { DB } from '../common/database/database.js'
import { notFound } from '../common/http/app-error.js'
import { defineEvent } from '../common/messaging/event.js'
import { enqueueEvent } from '../common/messaging/outbox.js'
import { users } from '../db/schema.js'
import type { Db, Tx, UserRow } from '../db/types.js'
import { RolesService } from './roles.service.js'

export const userRegistered = defineEvent(userRegisteredV1.type, userRegisteredV1.producer, userRegisteredV1.payload)

export type Profile = {
    id: string
    email: string
    displayName: string | null
    locale: Locale
    roles: string[]
    createdAt: string
}

@Injectable()
export class UsersService {
    constructor(
        @Inject(DB) private readonly db: Db,
        private readonly roles: RolesService,
    ) {}

    /**
     * The user behind a correct sign-in code, created on the first one in the
     * same transaction as the session; `id.user.registered.v1` goes to the outbox.
     */
    async findOrCreate(tx: Tx, email: string, locale: Locale): Promise<UserRow> {
        const [existing] = await tx.select().from(users).where(eq(users.email, email))
        if (existing) return existing
        const [created] = await tx
            .insert(users)
            .values({
                email,
                locale,
            })
            .onConflictDoNothing()
            .returning()
        if (!created) {
            // A concurrent sign-in of the same email won; use its row.
            const [winner] = await tx.select().from(users).where(eq(users.email, email))
            if (!winner) throw new Error('user vanished during sign-in')
            return winner
        }
        await enqueueEvent(
            tx,
            userRegistered.create({
                aggregateId: created.id,
                payload: {
                    userId: created.id,
                    locale: created.locale,
                    registeredAt: created.createdAt.toISOString(),
                },
            }),
        )
        return created
    }

    async get(executor: Db | Tx, userId: string): Promise<UserRow> {
        const [user] = await executor.select().from(users).where(eq(users.id, userId))
        if (!user) throw notFound('User')
        return user
    }

    async profile(userId: string): Promise<Profile> {
        const user = await this.get(this.db, userId)
        return this.toProfile(user, await this.roles.rolesOf(this.db, userId))
    }

    async update(
        userId: string,
        changes: {
            displayName?: string | null
            locale?: Locale
        },
    ): Promise<Profile> {
        await this.db
            .update(users)
            .set({
                ...changes,
                updatedAt: new Date(),
            })
            .where(eq(users.id, userId))
        return this.profile(userId)
    }

    toProfile(user: UserRow, roles: string[]): Profile {
        return {
            id: user.id,
            email: user.email,
            displayName: user.displayName,
            locale: user.locale,
            roles,
            createdAt: user.createdAt.toISOString(),
        }
    }
}
