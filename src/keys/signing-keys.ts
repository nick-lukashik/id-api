import { Inject, Injectable, type OnModuleInit } from '@nestjs/common'
import type { ConfigType } from '@nestjs/config'
import { ACCESS_TOKEN_ALGORITHM, ACCESS_TOKEN_TYPE } from '@nick-lukashik/auth'
import {
    calculateJwkThumbprint,
    createLocalJWKSet,
    exportJWK,
    importPKCS8,
    type JWK,
    type JWTVerifyGetKey,
    SignJWT,
} from 'jose'
import { tokenConfig } from '../config/config.js'

export type AccessTokenInput = {
    userId: string
    sessionId: string
    roles: string[]
    accessVersion: number
}

/**
 * The ES256 key that signs access tokens. Its public half, plus retired keys
 * still in their overlap (PREVIOUS_PUBLIC_KEYS), is the JWKS every API
 * verifies with: no shared secret. Rotation: publish the next key's public
 * half first, switch SIGNING_KEY_PEM, keep the old public key until the last
 * token signed with it has expired (5 minutes).
 */
@Injectable()
export class SigningKeys implements OnModuleInit {
    private privateKey!: CryptoKey
    private kid!: string
    private published!: JWK[]
    private localKeys!: JWTVerifyGetKey

    constructor(@Inject(tokenConfig.KEY) private readonly config: ConfigType<typeof tokenConfig>) {}

    async onModuleInit() {
        this.privateKey = await importPKCS8(this.config.privateKeyPem.replaceAll('\\n', '\n'), ACCESS_TOKEN_ALGORITHM, {
            extractable: true,
        })
        const current = await publicKeyOf(await exportJWK(this.privateKey))
        this.kid = current.kid
        const keys = new Map([
            [
                current.kid,
                current,
            ],
        ])
        for (const jwk of JSON.parse(this.config.previousPublicKeys) as JWK[]) {
            const key = await publicKeyOf(jwk)
            if (!keys.has(key.kid)) keys.set(key.kid, key)
        }
        this.published = [
            ...keys.values(),
        ]
        this.localKeys = createLocalJWKSet({
            keys: this.published,
        })
    }

    jwks() {
        return {
            keys: this.published,
        }
    }

    /** Verifies this service's own tokens without an HTTP round trip. */
    verificationKeys: JWTVerifyGetKey = (header, token) => this.localKeys(header, token)

    async sign(input: AccessTokenInput, now: Date) {
        const issuedAt = Math.floor(now.getTime() / 1000)
        const expiresAt = issuedAt + this.config.accessTtlSec
        const token = await new SignJWT({
            sid: input.sessionId,
            roles: input.roles,
            av: input.accessVersion,
        })
            .setProtectedHeader({
                alg: ACCESS_TOKEN_ALGORITHM,
                kid: this.kid,
                typ: ACCESS_TOKEN_TYPE,
            })
            .setSubject(input.userId)
            .setIssuer(this.config.issuer)
            .setAudience(this.config.audience)
            .setIssuedAt(issuedAt)
            .setExpirationTime(expiresAt)
            .sign(this.privateKey)
        return {
            token,
            expiresAt: new Date(expiresAt * 1000),
        }
    }
}

/** The public members of an ES256 (P-256) key under its RFC 7638 thumbprint. */
async function publicKeyOf(key: JWK) {
    if (key.kty !== 'EC' || key.crv !== 'P-256') throw new Error('Signing keys must be ES256 (EC P-256)')
    const jwk: JWK = {
        kty: key.kty,
        crv: key.crv,
        x: key.x,
        y: key.y,
    }
    const kid = await calculateJwkThumbprint(jwk)
    return {
        ...jwk,
        kid,
        alg: ACCESS_TOKEN_ALGORITHM,
        use: 'sig',
    }
}
