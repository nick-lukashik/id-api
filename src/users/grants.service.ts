import { Injectable } from '@nestjs/common'
import { type Grant, grantKey } from '@nick-lukashik/auth'
import { and, eq, gt, isNull, or, sql } from 'drizzle-orm'
import { grants, users } from '../db/schema.js'
import type { Db, Tx } from '../db/types.js'

/** What one subscription event says (see `pay.subscription.changed.v1`). */
export type SubscriptionAccess = {
    subscriptionId: string
    userId: string
    service: string
    plan: string
    /** The plan holds until then; null takes it away now. */
    accessUntil: Date | null
    version: number
}

/**
 * Paid plans of services, one row per subscription. Nothing has to run when a
 * period ends: tokens carry only the grants in force when they are issued
 * (every 5 minutes at the latest), so an expired one simply stops appearing.
 */
@Injectable()
export class GrantsService {
    /** `service:plan` of every grant in force right now, once each. */
    async activeOf(executor: Db | Tx, userId: string): Promise<Grant[]> {
        const rows = await executor
            .selectDistinct({
                service: grants.service,
                plan: grants.plan,
            })
            .from(grants)
            .where(
                and(
                    eq(grants.userId, userId),
                    isNull(grants.revokedAt),
                    or(isNull(grants.validUntil), gt(grants.validUntil, sql`now()`)),
                ),
            )
        return rows.map(row => grantKey(row.service, row.plan)).sort()
    }

    /**
     * Keeps the grant of one subscription in step with pay-api. A version not
     * newer than the one applied changes nothing, so a late or repeated event
     * never brings back a plan that was taken away. Returns whether anything changed.
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
            service: access.service,
            plan: access.plan,
            source: 'subscription' as const,
            sourceRef: access.subscriptionId,
            sourceVersion: access.version,
            validUntil: access.accessUntil,
            revokedAt: active ? null : now,
            updatedAt: now,
        }
        const written = await tx
            .insert(grants)
            .values(row)
            .onConflictDoUpdate({
                target: [
                    grants.source,
                    grants.sourceRef,
                ],
                set: {
                    service: row.service,
                    plan: row.plan,
                    sourceVersion: row.sourceVersion,
                    validUntil: row.validUntil,
                    revokedAt: row.revokedAt,
                    updatedAt: now,
                },
                setWhere: sql`${grants.sourceVersion} < ${access.version}`,
            })
            .returning({
                id: grants.id,
            })
        if (written.length === 0) return false
        await tx
            .update(users)
            .set({
                accessVersion: sql`${users.accessVersion} + 1`,
                updatedAt: now,
            })
            .where(eq(users.id, access.userId))
        return true
    }
}
