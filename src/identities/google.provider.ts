import type { ConfigType } from '@nestjs/config'
import { createRemoteJWKSet, jwtVerify } from 'jose'
import { z } from 'zod'
import { googleConfig } from '../config/config.js'

export type GoogleProfile = {
    /** Stable Google account id (`sub`). */
    subject: string
    email: string | null
    emailVerified: boolean
    /** Whether Google hosts the mailbox ({@link googleHostsEmail}). */
    hostedByGoogle: boolean
    name: string | null
}

/** What id-web got back from Google, and the secrets of its own request. */
export type GoogleCode = {
    code: string
    codeVerifier: string
    nonce: string
}

/**
 * Whether Google hosts the address, so that `email_verified` speaks of who holds the mailbox
 * now: Gmail, or a Workspace domain (`hd`). For any other address it only says the mailbox
 * answered when the Google account was made, and the mailbox may have changed hands since.
 */
export const googleHostsEmail = (email: string | null, hd: string | undefined) =>
    Boolean(hd) || Boolean(email?.endsWith('@gmail.com'))

/** Google answered, and the answer is "no": a bad, reused or foreign code. */
export class GoogleRejected extends Error {}
/** Google could not be reached; the person may retry. */
export class GoogleUnavailable extends Error {}

/** Authorization code (PKCE) in, verified ID token claims out. */
export abstract class GoogleProvider {
    abstract readonly enabled: boolean
    /** Where id-web sends the browser; a stand-in in tests. */
    abstract readonly authorizationEndpoint: string | null
    abstract readonly clientId: string | null
    abstract readonly redirectUri: string | null
    abstract verify(input: GoogleCode): Promise<GoogleProfile>
}

const claimsSchema = z.object({
    sub: z.string().min(1).max(255),
    email: z.string().max(254).optional(),
    // Older tokens carried the flag as a string.
    email_verified: z
        .union([
            z.boolean(),
            z.enum([
                'true',
                'false',
            ]),
        ])
        .optional(),
    name: z.string().max(200).optional(),
    nonce: z.string().optional(),
    hd: z.string().optional(),
})

/** Google OpenID Connect: the token endpoint, then the ID token checks of Google's docs. */
export class GoogleOidcProvider extends GoogleProvider {
    readonly enabled = true
    readonly authorizationEndpoint = 'https://accounts.google.com/o/oauth2/v2/auth'
    private readonly keys = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'))

    constructor(
        readonly clientId: string,
        private readonly clientSecret: string,
        readonly redirectUri: string,
    ) {
        super()
    }

    async verify({ code, codeVerifier, nonce }: GoogleCode): Promise<GoogleProfile> {
        let response: Response
        try {
            response = await fetch('https://oauth2.googleapis.com/token', {
                method: 'POST',
                headers: {
                    'content-type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    grant_type: 'authorization_code',
                    code,
                    code_verifier: codeVerifier,
                    client_id: this.clientId,
                    client_secret: this.clientSecret,
                    redirect_uri: this.redirectUri,
                }),
                signal: AbortSignal.timeout(8_000),
            })
        } catch (error) {
            throw new GoogleUnavailable((error as Error).message)
        }
        if (response.status >= 500) throw new GoogleUnavailable(`google ${response.status}`)
        const body = (await response.json().catch(() => ({}))) as {
            id_token?: string
            error?: string
        }
        if (!response.ok || !body.id_token) throw new GoogleRejected(body.error ?? `google ${response.status}`)

        let claims: z.infer<typeof claimsSchema>
        try {
            const { payload } = await jwtVerify(body.id_token, this.keys, {
                issuer: [
                    'https://accounts.google.com',
                    'accounts.google.com',
                ],
                audience: this.clientId,
                algorithms: [
                    'RS256',
                ],
            })
            claims = claimsSchema.parse(payload)
        } catch {
            throw new GoogleRejected('invalid id token')
        }
        if (claims.nonce !== nonce) throw new GoogleRejected('nonce mismatch')
        const email = claims.email?.toLowerCase() ?? null
        return {
            subject: claims.sub,
            email,
            emailVerified: claims.email_verified === true || claims.email_verified === 'true',
            hostedByGoogle: googleHostsEmail(email, claims.hd),
            name: claims.name ?? null,
        }
    }
}

/** Without GOOGLE_* the button is hidden and every call is 404. */
export class DisabledGoogleProvider extends GoogleProvider {
    readonly enabled = false
    readonly authorizationEndpoint = null
    readonly clientId = null
    readonly redirectUri = null

    async verify(): Promise<GoogleProfile> {
        throw new GoogleRejected('google sign-in is not configured')
    }
}

export const googleProvider = {
    provide: GoogleProvider,
    inject: [
        googleConfig.KEY,
    ],
    useFactory: (config: ConfigType<typeof googleConfig>): GoogleProvider =>
        config.clientId && config.clientSecret && config.redirectUri
            ? new GoogleOidcProvider(config.clientId, config.clientSecret, config.redirectUri)
            : new DisabledGoogleProvider(),
}
