import { sql } from 'drizzle-orm'
import { check, index, integer, pgTable, text, timestamp, uniqueIndex, uuid } from 'drizzle-orm/pg-core'

// Platform tables every service with events carries: outbox and inbox.
export { inbox, outbox } from '../common/messaging/outbox.schema.js'

/** Millisecond precision, so an ISO string from JSON round-trips exactly (cursors). */
const at = (name: string) =>
    timestamp(name, {
        withTimezone: true,
        precision: 3,
    })

/** A person. `email` (lower case) is the anchor identity; the row is created by the first correct code. */
export const users = pgTable(
    'users',
    {
        id: uuid('id').primaryKey().default(sql`uuidv7()`),
        email: text('email').notNull(),
        displayName: text('display_name'),
        locale: text('locale', {
            enum: [
                'en',
                'ru',
            ],
        })
            .notNull()
            .default('en'),
        status: text('status', {
            enum: [
                'active',
                'suspended',
            ],
        })
            .notNull()
            .default('active'),
        /** Bumped when roles or the status change; carried in access tokens as `av`. */
        accessVersion: integer('access_version').notNull().default(0),
        createdAt: at('created_at').notNull().defaultNow(),
        updatedAt: at('updated_at').notNull().defaultNow(),
    },
    t => [
        uniqueIndex('users_email_uq').on(t.email),
        check('users_email_lower', sql`${t.email} = lower(${t.email})`),
        check('users_display_name_length', sql`char_length(${t.displayName}) between 1 and 80`),
    ],
)

/**
 * One sign-in attempt by email code. Only an HMAC of the code is stored; the
 * user is created only after a correct code, so asking for a code reveals
 * nothing about existing accounts.
 */
export const loginChallenges = pgTable(
    'login_challenges',
    {
        id: uuid('id').primaryKey(),
        email: text('email').notNull(),
        codeHash: text('code_hash').notNull(),
        locale: text('locale', {
            enum: [
                'en',
                'ru',
            ],
        }).notNull(),
        expiresAt: at('expires_at').notNull(),
        attempts: integer('attempts').notNull().default(0),
        consumedAt: at('consumed_at'),
        deliveryStatus: text('delivery_status', {
            enum: [
                'pending',
                'accepted',
                'failed',
            ],
        })
            .notNull()
            .default('pending'),
        createdAt: at('created_at').notNull().defaultNow(),
    },
    t => [
        index('login_challenges_email_idx').on(t.email, t.createdAt),
        index('login_challenges_expires_idx').on(t.expiresAt),
    ],
)

/** Session metadata. The refresh token family lives in Redis under the session id. */
export const sessions = pgTable(
    'sessions',
    {
        id: uuid('id').primaryKey().default(sql`uuidv7()`),
        userId: uuid('user_id')
            .notNull()
            .references(() => users.id, {
                onDelete: 'cascade',
            }),
        authMethod: text('auth_method', {
            enum: [
                'email',
            ],
        }).notNull(),
        userAgent: text('user_agent'),
        ip: text('ip'),
        createdAt: at('created_at').notNull().defaultNow(),
        lastActiveAt: at('last_active_at').notNull().defaultNow(),
        revokedAt: at('revoked_at'),
        revokedReason: text('revoked_reason', {
            enum: [
                'logout',
                'user',
                'admin',
                'reuse_detected',
            ],
        }),
    },
    t => [
        index('sessions_user_idx').on(t.userId, t.createdAt.desc()),
    ],
)

/** Platform roles (owner, support). Paid access never lives here. */
export const roleBindings = pgTable(
    'role_bindings',
    {
        id: uuid('id').primaryKey().default(sql`uuidv7()`),
        userId: uuid('user_id')
            .notNull()
            .references(() => users.id, {
                onDelete: 'cascade',
            }),
        role: text('role').notNull(),
        reason: text('reason').notNull(),
        grantedBy: text('granted_by').notNull(),
        createdAt: at('created_at').notNull().defaultNow(),
        revokedAt: at('revoked_at'),
    },
    t => [
        uniqueIndex('role_bindings_active_uq').on(t.userId, t.role).where(sql`${t.revokedAt} is null`),
    ],
)
