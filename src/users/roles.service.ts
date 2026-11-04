import { Inject, Injectable } from '@nestjs/common'
import { isRole, type Role } from '@nick-lukashik/auth'
import { and, eq, isNull, sql } from 'drizzle-orm'
import { DB } from '../common/database/database.js'
import { AppError } from '../common/http/app-error.js'
import { roleBindings, users } from '../db/schema.js'
import type { Db, Tx } from '../db/types.js'

/**
 * Staff roles, granted by hand. Every change bumps the user's access version,
 * so services see it on the next token. Paid plans are grants (grants.service.ts).
 */
@Injectable()
export class RolesService {
    constructor(@Inject(DB) private readonly db: Db) {}

    async rolesOf(executor: Db | Tx, userId: string): Promise<Role[]> {
        const rows = await executor
            .select({
                role: roleBindings.role,
            })
            .from(roleBindings)
            .where(and(eq(roleBindings.userId, userId), isNull(roleBindings.revokedAt)))
        return rows.map(row => row.role).filter(isRole)
    }

    /** Grants a role by email (the command line of the first owner); idempotent. */
    async grant(email: string, role: Role, grantedBy: string, reason: string) {
        return this.db.transaction(async tx => {
            const [user] = await tx
                .select({
                    id: users.id,
                })
                .from(users)
                .where(eq(users.email, email.trim().toLowerCase()))
            if (!user) throw new AppError('NOT_FOUND', 'No user with this email: they sign in once first')
            const inserted = await tx
                .insert(roleBindings)
                .values({
                    userId: user.id,
                    role,
                    reason,
                    grantedBy,
                })
                .onConflictDoNothing()
                .returning({
                    id: roleBindings.id,
                })
            if (inserted.length > 0) {
                await tx
                    .update(users)
                    .set({
                        accessVersion: sql`${users.accessVersion} + 1`,
                        updatedAt: new Date(),
                    })
                    .where(eq(users.id, user.id))
            }
            return {
                userId: user.id,
                granted: inserted.length > 0,
            }
        })
    }
}
