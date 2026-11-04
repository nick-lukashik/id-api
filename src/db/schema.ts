import { sql } from 'drizzle-orm'
import {
    bigint,
    boolean,
    check,
    customType,
    index,
    integer,
    pgTable,
    text,
    timestamp,
    uniqueIndex,
    uuid,
} from 'drizzle-orm/pg-core'

// Platform tables every service with events carries: outbox and inbox.
export { inbox, outbox } from '../common/messaging/outbox.schema.js'

/** Millisecond precision, so an ISO string from JSON round-trips exactly (cursors). */
const at = (name: string) =>
    timestamp(name, {
        withTimezone: true,
        precision: 3,
    })

/** Raw bytes (passkey public keys). */
const bytea = customType<{
    data: Uint8Array<ArrayBuffer>
    driverData: Buffer
}>({
    dataType: () => 'bytea',
    toDriver: value => Buffer.from(value),
    // A copy: the driver's Buffer may share a pooled ArrayBuffer.
    fromDriver: value => new Uint8Array(value),
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
                'google',
                'passkey',
                'sso',
            ],
        }).notNull(),
        /** The app this session belongs to (`landing-web`); null for id-web's own sessions. */
        clientId: text('client_id'),
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

/**
 * Roles of a user. Staff roles (owner, support) are granted by hand
 * (`source = manual`) and never expire. A paid role (subscriber) has one row
 * per subscription (`source = subscription`, `source_ref` = its id), kept in
 * step with `pay.subscription.changed.v1` and valid until `expires_at`.
 */
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
        source: text('source', {
            enum: [
                'manual',
                'subscription',
            ],
        })
            .notNull()
            .default('manual'),
        sourceRef: text('source_ref'),
        /** The `version` of the last subscription event applied: an older one changes nothing. */
        sourceVersion: integer('source_version'),
        expiresAt: at('expires_at'),
        createdAt: at('created_at').notNull().defaultNow(),
        revokedAt: at('revoked_at'),
    },
    t => [
        uniqueIndex('role_bindings_active_uq')
            .on(t.userId, t.role)
            .where(sql`${t.revokedAt} is null and ${t.source} = 'manual'`),
        uniqueIndex('role_bindings_source_uq').on(t.source, t.sourceRef).where(sql`${t.sourceRef} is not null`),
        check(
            'role_bindings_source_ref',
            sql`(${t.source} = 'manual') = (${t.sourceRef} is null and ${t.expiresAt} is null)`,
        ),
    ],
)

/**
 * A Google account linked to a user (`sub` of Google's ID token). Signing in
 * with Google finds the user here; an unknown Google account whose email is
 * already taken is not linked by itself: the owner links it while signed in.
 */
export const identities = pgTable(
    'identities',
    {
        id: uuid('id').primaryKey().default(sql`uuidv7()`),
        userId: uuid('user_id')
            .notNull()
            .references(() => users.id, {
                onDelete: 'cascade',
            }),
        provider: text('provider', {
            enum: [
                'google',
            ],
        }).notNull(),
        subject: text('subject').notNull(),
        email: text('email'),
        createdAt: at('created_at').notNull().defaultNow(),
    },
    t => [
        uniqueIndex('identities_provider_subject_uq').on(t.provider, t.subject),
        uniqueIndex('identities_user_provider_uq').on(t.userId, t.provider),
    ],
)

/** A passkey (WebAuthn credential) of a user. The private key never leaves the person's device. */
export const passkeys = pgTable(
    'passkeys',
    {
        id: uuid('id').primaryKey().default(sql`uuidv7()`),
        userId: uuid('user_id')
            .notNull()
            .references(() => users.id, {
                onDelete: 'cascade',
            }),
        /** base64url, as the browser names it. */
        credentialId: text('credential_id').notNull(),
        /** COSE public key. */
        publicKey: bytea('public_key').notNull(),
        signCount: bigint('sign_count', {
            mode: 'number',
        })
            .notNull()
            .default(0),
        transports: text('transports').array().notNull().default(sql`'{}'::text[]`),
        aaguid: text('aaguid').notNull(),
        /** The RP ID it was created for; one of another RP signs nobody in. */
        rpId: text('rp_id').notNull(),
        /** Synced by its provider (iCloud Keychain, Google Password Manager). */
        backupEligible: boolean('backup_eligible').notNull(),
        backedUp: boolean('backed_up').notNull(),
        name: text('name').notNull(),
        createdAt: at('created_at').notNull().defaultNow(),
        lastUsedAt: at('last_used_at'),
    },
    t => [
        uniqueIndex('passkeys_credential_id_uq').on(t.credentialId),
        index('passkeys_user_idx').on(t.userId, t.createdAt),
        check('passkeys_name_length', sql`char_length(${t.name}) between 1 and 60`),
    ],
)

/**
 * One-time codes of sign-in for the platform's apps (authorization code with
 * PKCE): 60 seconds, bound to the client, its exact redirect URI and the
 * challenge. Only a SHA-256 of the code is stored.
 */
export const authorizationCodes = pgTable(
    'authorization_codes',
    {
        codeHash: text('code_hash').primaryKey(),
        clientId: text('client_id').notNull(),
        redirectUri: text('redirect_uri').notNull(),
        codeChallenge: text('code_challenge').notNull(),
        userId: uuid('user_id')
            .notNull()
            .references(() => users.id, {
                onDelete: 'cascade',
            }),
        expiresAt: at('expires_at').notNull(),
        consumedAt: at('consumed_at'),
        createdAt: at('created_at').notNull().defaultNow(),
    },
    t => [
        index('authorization_codes_expires_idx').on(t.expiresAt),
    ],
)
