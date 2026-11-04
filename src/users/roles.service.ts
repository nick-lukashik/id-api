import { Inject, Injectable } from '@nestjs/common'
import { isRole, type PaidRole, type Role, type StaffRole } from '@nick-lukashik/auth'
import { and, eq, gt, isNull, or, sql } from 'drizzle-orm'
import { DB } from '../common/database/database.js'
import { AppError } from '../common/http/app-error.js'
import { roleBindings, users } from '../db/schema.js'
import type { Db, Tx } from '../db/types.js'

/** What a subscription event says about one subscription (see `pay.subscription.changed.v1`). */
export type SubscriptionAccess = {
    subscriptionId: string
    userId: string
    plan: string
    role: PaidRole
    /** The role holds until then; null takes it away now. */
    accessUntil: Date | null
    version: number
}

/** Platform roles. Every change bumps the user's access version, so services see it on the next token. */
@Injectable()
export class RolesService {
    constructor(@Inject(DB) private readonly db: Db) {}

    /** Roles in force right now: not revoked, not expired. A paid role ends without any job. */
    async rolesOf(executor: Db | Tx, userId: string): Promise<Role[]> {
        const rows = await executor
            .selectDistinct({
                role: roleBindings.role,
            })
            .from(roleBindings)
            .where(
                and(
                    eq(roleBindings.userId, userId),
                    isNull(roleBindings.revokedAt),
                    or(isNull(roleBindings.expiresAt), gt(roleBindings.expiresAt, sql`now()`)),
                ),
            )
        return rows
            .map(row => row.role)
            .filter(isRole)
            .sort()
    }

    /** Grants a staff role by email (the command line of the first owner); idempotent. Paid roles come only from subscriptions. */
    async grant(email: string, role: StaffRole, grantedBy: string, reason: string) {
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
            if (inserted.length > 0) await bumpAccess(tx, user.id)
            return {
                userId: user.id,
                granted: inserted.length > 0,
            }
        })
    }

    /**
     * Keeps the paid role of one subscription in step with pay-api: one row per
     * subscription, valid until `accessUntil`. A version not newer than the one
     * applied changes nothing, so a late or repeated event never brings back a
     * role that was taken away. Returns whether anything changed.
     */
    async applySubscription(tx: Tx, access: SubscriptionAccess): Promise<boolean> {
        const [user] = await tx
            .select({
                id: users.id,
            })
            .from(users)
            .where(eq(users.id, access.userId))
        if (!user) return false
        const now = new Date()
        const active = access.accessUntil !== null && access.accessUntil > now
        const row = {
            userId: access.userId,
            role: access.role,
            reason: `subscription ${access.plan}`,
            grantedBy: 'pay-api',
            source: 'subscription' as const,
            sourceRef: access.subscriptionId,
            sourceVersion: access.version,
            expiresAt: access.accessUntil,
            revokedAt: active ? null : now,
        }
        const written = await tx
            .insert(roleBindings)
            .values(row)
            .onConflictDoUpdate({
                target: [
                    roleBindings.source,
                    roleBindings.sourceRef,
                ],
                targetWhere: sql`${roleBindings.sourceRef} is not null`,
                set: {
                    role: row.role,
                    reason: row.reason,
                    sourceVersion: row.sourceVersion,
                    expiresAt: row.expiresAt,
                    revokedAt: row.revokedAt,
                },
                setWhere: sql`${roleBindings.sourceVersion} < ${access.version}`,
            })
            .returning({
                id: roleBindings.id,
            })
        if (written.length === 0) return false
        await bumpAccess(tx, access.userId)
        return true
    }
}

async function bumpAccess(tx: Tx, userId: string) {
    await tx
        .update(users)
        .set({
            accessVersion: sql`${users.accessVersion} + 1`,
            updatedAt: new Date(),
        })
        .where(eq(users.id, userId))
}
