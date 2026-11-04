import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { createAccessTokenVerifier } from '@nick-lukashik/auth'
import { sql } from 'drizzle-orm'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { SubscriptionsConsumer } from '../src/users/subscriptions.consumer.js'
import { SoftwareAuthenticator } from './authenticator.js'
import { SITE_CALLBACK, startApp, type TestApp } from './harness.js'

let t: TestApp

beforeAll(async () => {
    t = await startApp()
})
afterAll(async () => {
    await t?.close()
})

type Tokens = {
    accessToken: string
    refreshToken: string
    sessionId: string
    user: {
        id: string
        email: string
        displayName: string | null
        roles: string[]
    }
}

async function emailSignIn(email: string): Promise<Tokens> {
    await t
        .http()
        .post('/api/v1/login/email')
        .send({
            email,
        })
        .expect(202)
    const { code, challengeId } = t.delivery.last()
    const verified = await t
        .http()
        .post('/api/v1/login/email/verify')
        .send({
            challengeId,
            code,
        })
        .expect(200)
    return verified.body
}

const bearer = (session: { accessToken: string }) => `Bearer ${session.accessToken}`

/** For helpers that await a step first: the status of the response they end with. */
async function status<
    T extends {
        status: number
        body: unknown
    },
>(pending: Promise<T>, expected: number) {
    const response = await pending
    expect(response.status, JSON.stringify(response.body)).toBe(expected)
    return response
}

const verifier = () =>
    createAccessTokenVerifier({
        jwksUrl: `${t.url}/.well-known/jwks.json`,
        issuer: 'https://id.example.test',
        audience: 'nick-lukashik',
    })

describe('sign-in with Google', () => {
    it('creates an account for a new Google account and signs it in again', async () => {
        const config = await t.http().get('/api/v1/login/google/config').expect(200)
        expect(config.body).toMatchObject({
            enabled: true,
            clientId: t.google.clientId,
        })
        const code = t.google.account({
            subject: 'g-new',
            email: 'new.person@gmail.com',
            emailVerified: true,
            name: 'New Person',
        })
        const first = await t
            .http()
            .post('/api/v1/login/google')
            .send({
                ...code,
                locale: 'ru',
            })
            .expect(200)
        expect(first.body.user).toMatchObject({
            email: 'new.person@gmail.com',
            displayName: 'New Person',
            locale: 'ru',
        })
        const again = await t.http().post('/api/v1/login/google').send(code).expect(200)
        expect(again.body.user.id).toBe(first.body.user.id)
        const sessions = await t.db.execute<{
            auth_method: string
        }>(sql`select auth_method from sessions where user_id = ${first.body.user.id}`)
        expect(sessions.rows.map(row => row.auth_method)).toEqual([
            'google',
            'google',
        ])
    })

    it('never attaches a Google account to an existing email by itself', async () => {
        const owner = await emailSignIn('taken@example.com')
        const code = t.google.account({
            subject: 'g-taken',
            email: 'taken@example.com',
            emailVerified: true,
            name: null,
        })
        const refused = await t.http().post('/api/v1/login/google').send(code).expect(409)
        expect(refused.body.details[0]).toEqual({
            path: 'email',
            message: 'link_required',
        })

        // The owner links it while signed in; then it signs in.
        await t.http().post('/api/v1/me/identities/google').set('authorization', bearer(owner)).send(code).expect(200)
        const signedIn = await t.http().post('/api/v1/login/google').send(code).expect(200)
        expect(signedIn.body.user.id).toBe(owner.user.id)

        // Someone else cannot take it over.
        const other = await emailSignIn('other@example.com')
        const stolen = await t
            .http()
            .post('/api/v1/me/identities/google')
            .set('authorization', bearer(other))
            .send(code)
            .expect(409)
        expect(stolen.body.details[0].message).toBe('in_use')

        await t.http().delete('/api/v1/me/identities/google').set('authorization', bearer(owner)).expect(204)
        const listed = await t.http().get('/api/v1/me/identities').set('authorization', bearer(owner)).expect(200)
        expect(listed.body.items).toEqual([])
    })

    it('refuses an unverified email, a wrong nonce and a bad code', async () => {
        const unverified = t.google.account({
            subject: 'g-unverified',
            email: 'maybe@example.com',
            emailVerified: false,
            name: null,
        })
        const answer = await t.http().post('/api/v1/login/google').send(unverified).expect(422)
        expect(answer.body.details[0].message).toBe('unverified')

        const code = t.google.account({
            subject: 'g-nonce',
            email: 'nonce@example.com',
            emailVerified: true,
            name: null,
        })
        await t
            .http()
            .post('/api/v1/login/google')
            .send({
                ...code,
                nonce: 'x'.repeat(24),
            })
            .expect(422)
        await t
            .http()
            .post('/api/v1/login/google')
            .send({
                ...code,
                code: 'code-nobody',
            })
            .expect(422)
    })
})

describe('passkeys', () => {
    async function register(session: Tokens, device: SoftwareAuthenticator, name = 'Laptop') {
        const begun = await t
            .http()
            .post('/api/v1/me/passkeys/options')
            .set('authorization', bearer(session))
            .expect(200)
        expect(begun.body.options.rp.id).toBe('localhost')
        expect(begun.body.options.authenticatorSelection).toMatchObject({
            residentKey: 'required',
            userVerification: 'required',
        })
        return t
            .http()
            .post('/api/v1/me/passkeys')
            .set('authorization', bearer(session))
            .send({
                challengeId: begun.body.challengeId,
                name,
                response: device.register(begun.body.options),
            })
    }

    async function passkeySignIn(
        device: SoftwareAuthenticator,
        ceremony: Parameters<SoftwareAuthenticator['assert']>[1] = {},
    ) {
        const begun = await t.http().post('/api/v1/login/passkey/options').expect(200)
        return t
            .http()
            .post('/api/v1/login/passkey/verify')
            .send({
                challengeId: begun.body.challengeId,
                response: device.assert(begun.body.options, ceremony),
            })
    }

    it('adds a passkey after a fresh sign-in and signs in with it, no email needed', async () => {
        const session = await emailSignIn('keys@example.com')
        const device = new SoftwareAuthenticator({
            synced: true,
        })
        const added = await status(register(session, device), 201)
        expect(added.body).toMatchObject({
            name: 'Laptop',
            synced: true,
            usable: true,
        })

        const signedIn = await status(passkeySignIn(device), 200)
        expect(signedIn.body.user.id).toBe(session.user.id)
        const claims = await verifier()(signedIn.body.accessToken)
        expect(claims.userId).toBe(session.user.id)

        const listed = await t.http().get('/api/v1/me/passkeys').set('authorization', bearer(session)).expect(200)
        expect(listed.body.items).toHaveLength(1)
        expect(listed.body.items[0].lastUsedAt).not.toBeNull()
        expect(listed.body.items[0].credentialId).toBe(
            device.assert({
                challenge: 'x',
                rpId: 'localhost',
            }).id,
        )
    })

    it('asks an older session to sign in again before it adds a passkey', async () => {
        const session = await emailSignIn('old-session@example.com')
        await t.db.execute(
            sql`update sessions set created_at = now() - interval '1 hour' where id = ${session.sessionId}`,
        )
        const refused = await t
            .http()
            .post('/api/v1/me/passkeys/options')
            .set('authorization', bearer(session))
            .expect(403)
        expect(refused.body.details[0].message).toBe('reauthentication_required')
    })

    it('refuses another origin, a used challenge, a missing user verification and a cloned key', async () => {
        const session = await emailSignIn('strict@example.com')
        const device = new SoftwareAuthenticator({
            counting: true,
        })
        await status(register(session, device), 201)

        const phishing = await status(
            passkeySignIn(device, {
                origin: 'https://id.evil.test',
            }),
            422,
        )
        expect(phishing.body.details[0].message).toBe('rejected')
        await status(
            passkeySignIn(device, {
                userVerified: false,
            }),
            422,
        )

        const begun = await t.http().post('/api/v1/login/passkey/options').expect(200)
        const answer = device.assert(begun.body.options)
        await t
            .http()
            .post('/api/v1/login/passkey/verify')
            .send({
                challengeId: begun.body.challengeId,
                response: answer,
            })
            .expect(200)
        const replay = await t
            .http()
            .post('/api/v1/login/passkey/verify')
            .send({
                challengeId: begun.body.challengeId,
                response: answer,
            })
            .expect(422)
        expect(replay.body.details[0].message).toBe('stale')

        // A copy of the key: a genuine signature with a counter that did not grow.
        await status(
            passkeySignIn(device, {
                counter: 1,
            }),
            422,
        )
    })

    it('says a passkey the account no longer has is unknown, and removes only its own', async () => {
        const session = await emailSignIn('remove@example.com')
        const device = new SoftwareAuthenticator()
        const added = await status(register(session, device), 201)

        const stranger = await emailSignIn('stranger@example.com')
        await t.http().delete(`/api/v1/me/passkeys/${added.body.id}`).set('authorization', bearer(stranger)).expect(404)
        await t.http().delete(`/api/v1/me/passkeys/${added.body.id}`).set('authorization', bearer(session)).expect(204)
        const gone = await status(passkeySignIn(device), 422)
        expect(gone.body.details[0].message).toBe('unknown')
    })
})

describe('sign-in of the other apps', () => {
    const verifierPair = () => {
        const codeVerifier = randomBytes(48).toString('base64url')
        return {
            codeVerifier,
            codeChallenge: createHash('sha256').update(codeVerifier).digest('base64url'),
        }
    }

    function authorize(session: Tokens, codeChallenge: string, redirectUri = SITE_CALLBACK) {
        return t.http().post('/api/v1/oauth/authorize').set('authorization', bearer(session)).send({
            clientId: 'landing-web',
            redirectUri,
            codeChallenge,
            codeChallengeMethod: 'S256',
        })
    }

    const exchange = (code: string, codeVerifier: string, redirectUri = SITE_CALLBACK) =>
        t.http().post('/api/v1/oauth/token').send({
            grantType: 'authorization_code',
            clientId: 'landing-web',
            redirectUri,
            code,
            codeVerifier,
        })

    it('knows only registered apps with their exact callback', async () => {
        await t
            .http()
            .get('/api/v1/oauth/clients/landing-web')
            .query({
                redirectUri: SITE_CALLBACK,
            })
            .expect(200)
        await t
            .http()
            .get('/api/v1/oauth/clients/landing-web')
            .query({
                redirectUri: `${SITE_CALLBACK}?x=1`,
            })
            .expect(422)
        await t
            .http()
            .get('/api/v1/oauth/clients/roulette-web')
            .query({
                redirectUri: SITE_CALLBACK,
            })
            .expect(422)
    })

    it('gives the app its own session for a one-time code and the PKCE verifier', async () => {
        const session = await emailSignIn('sso@example.com')
        const pair = verifierPair()
        const issued = await authorize(session, pair.codeChallenge).expect(200)

        const app = await exchange(issued.body.code, pair.codeVerifier).expect(200)
        expect(app.body.sessionId).not.toBe(session.sessionId)
        const claims = await verifier()(app.body.accessToken)
        expect(claims.userId).toBe(session.user.id)

        // Once only.
        await exchange(issued.body.code, pair.codeVerifier).expect(422)

        const listed = await t.http().get('/api/v1/me/sessions').set('authorization', bearer(session)).expect(200)
        expect(listed.body.items).toContainEqual(
            expect.objectContaining({
                id: app.body.sessionId,
                authMethod: 'sso',
                clientId: 'landing-web',
            }),
        )

        // "Sign out everywhere else" reaches the app's session too.
        await t.http().post('/api/v1/me/sessions/revoke-others').set('authorization', bearer(session)).expect(200)
        await t
            .http()
            .post('/api/v1/sessions/refresh')
            .send({
                refreshToken: app.body.refreshToken,
            })
            .expect(401)
    })

    it('refuses a wrong verifier or callback, and the code is spent by the failure', async () => {
        const session = await emailSignIn('pkce@example.com')
        const pair = verifierPair()
        const issued = await authorize(session, pair.codeChallenge).expect(200)
        await exchange(issued.body.code, verifierPair().codeVerifier).expect(422)
        await exchange(issued.body.code, pair.codeVerifier).expect(422)

        const again = await authorize(session, pair.codeChallenge).expect(200)
        await exchange(again.body.code, pair.codeVerifier, 'https://evil.example.test/auth/callback').expect(422)

        await authorize(session, pair.codeChallenge, 'https://evil.example.test/auth/callback').expect(422)
        await t.http().post('/api/v1/oauth/authorize').send({}).expect(401)
    })
})

describe('roles from a subscription', () => {
    const event = (payload: Record<string, unknown>) => ({
        eventId: randomUUID(),
        type: 'pay.subscription.changed.v1',
        producer: 'pay',
        occurredAt: new Date().toISOString(),
        aggregateId: String(payload.subscriptionId),
        payload: {
            plan: 'monthly',
            role: 'subscriber',
            changedAt: new Date().toISOString(),
            ...payload,
        },
    })
    const rolesOf = async (session: Tokens) => {
        const refreshed = await t
            .http()
            .post('/api/v1/sessions/refresh')
            .send({
                refreshToken: session.refreshToken,
            })
            .expect(200)
        session.refreshToken = refreshed.body.refreshToken
        return (await verifier()(refreshed.body.accessToken)).roles
    }

    it('gives the role for the paid period and takes it away', async () => {
        const session = await emailSignIn('subscriber@example.com')
        const consumer = t.app.get(SubscriptionsConsumer)
        const subscriptionId = randomUUID()
        const inAMonth = new Date(Date.now() + 30 * 86_400_000).toISOString()

        await consumer.handle(
            event({
                subscriptionId,
                userId: session.user.id,
                accessUntil: inAMonth,
                version: 1,
            }),
        )
        expect(await rolesOf(session)).toEqual([
            'subscriber',
        ])

        // A late older event changes nothing; the refund (newer) ends it now.
        await consumer.handle(
            event({
                subscriptionId,
                userId: session.user.id,
                accessUntil: null,
                version: 3,
            }),
        )
        await consumer.handle(
            event({
                subscriptionId,
                userId: session.user.id,
                accessUntil: inAMonth,
                version: 2,
            }),
        )
        expect(await rolesOf(session)).toEqual([])
    })

    it('lets a paid period run out by itself', async () => {
        const session = await emailSignIn('lapsed@example.com')
        await t.app.get(SubscriptionsConsumer).handle(
            event({
                subscriptionId: randomUUID(),
                userId: session.user.id,
                accessUntil: new Date(Date.now() + 60_000).toISOString(),
                version: 1,
            }),
        )
        expect(await rolesOf(session)).toEqual([
            'subscriber',
        ])
        await t.db.execute(
            sql`update role_bindings set expires_at = now() - interval '1 second' where user_id = ${session.user.id}`,
        )
        expect(await rolesOf(session)).toEqual([])
    })
})
