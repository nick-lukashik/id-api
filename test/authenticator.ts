import { createHash, generateKeyPairSync, type KeyObject, randomBytes, sign } from 'node:crypto'
import type {
    AuthenticationResponseJSON,
    PublicKeyCredentialCreationOptionsJSON,
    PublicKeyCredentialRequestOptionsJSON,
    RegistrationResponseJSON,
} from '@simplewebauthn/server'
import { isoCBOR } from '@simplewebauthn/server/helpers'

/** Where id-web runs in local development and tests (port 3100). */
export const TEST_ORIGIN = 'http://localhost:3100'
export const TEST_RP_ID = 'localhost'

// Authenticator data flags (WebAuthn §6.1).
const UP = 0x01
const UV = 0x04
const BE = 0x08
const BS = 0x10
const AT = 0x40

const b64 = (bytes: Uint8Array | string) => Buffer.from(bytes).toString('base64url')
const sha256 = (data: Uint8Array | string) => createHash('sha256').update(data).digest()
const u32 = (value: number) => {
    const buffer = Buffer.alloc(4)
    buffer.writeUInt32BE(value)
    return buffer
}

type Credential = {
    id: Buffer
    privateKey: KeyObject
    /** base64url user handle from the creation options. */
    userHandle: string
    rpId: string
    counter: number
}

/** What the browser and the authenticator put in, and may get wrong. */
export type Ceremony = {
    /** The page origin the browser reports; id-web's by default. */
    origin?: string
    /** The RP ID the authenticator signs for. */
    rpId?: string
    /** User verification (fingerprint, PIN) happened; true by default. */
    userVerified?: boolean
    /** Sign this challenge instead of the one in the options. */
    challenge?: string
}

/**
 * A software passkey authenticator for integration tests: an ES256 key per
 * credential in memory, discoverable credentials holding the user handle
 * of the options, and "none" attestation, as platform passkeys send it.
 * It builds exactly what @simplewebauthn/browser would post.
 */
export class SoftwareAuthenticator {
    readonly aaguid = randomBytes(16)
    readonly credentials: Credential[] = []

    constructor(
        private readonly traits: {
            /** Hardware keys count signatures; synced passkeys always say 0. */
            counting?: boolean
            /** A synced (backup eligible) passkey. */
            synced?: boolean
        } = {},
    ) {}

    register(
        options: PublicKeyCredentialCreationOptionsJSON,
        ceremony: Ceremony & {
            /** Claim this credential id (base64url) instead of a new random one. */
            credentialId?: string
        } = {},
    ): RegistrationResponseJSON {
        const rpId = ceremony.rpId ?? options.rp.id ?? TEST_RP_ID
        const { privateKey, publicKey } = generateKeyPairSync('ec', {
            namedCurve: 'P-256',
        })
        const jwk = publicKey.export({
            format: 'jwk',
        })
        const cose = isoCBOR.encode(
            new Map<number, number | Uint8Array>([
                [
                    1,
                    2,
                ], // kty: EC2
                [
                    3,
                    -7,
                ], // alg: ES256
                [
                    -1,
                    1,
                ], // crv: P-256
                [
                    -2,
                    Buffer.from(jwk.x ?? '', 'base64url'),
                ],
                [
                    -3,
                    Buffer.from(jwk.y ?? '', 'base64url'),
                ],
            ]),
        )
        const credential: Credential = {
            id: ceremony.credentialId ? Buffer.from(ceremony.credentialId, 'base64url') : randomBytes(32),
            privateKey,
            userHandle: options.user.id,
            rpId,
            counter: 0,
        }
        this.credentials.push(credential)
        const length = Buffer.alloc(2)
        length.writeUInt16BE(credential.id.length)
        const authData = Buffer.concat([
            sha256(rpId),
            Buffer.from([
                this.flags(ceremony) | AT,
            ]),
            u32(0),
            this.aaguid,
            length,
            credential.id,
            cose,
        ])
        const attestationObject = isoCBOR.encode(
            new Map<string, string | Uint8Array | Map<string, never>>([
                [
                    'fmt',
                    'none',
                ],
                [
                    'attStmt',
                    new Map<string, never>(),
                ],
                [
                    'authData',
                    authData,
                ],
            ]),
        )
        return {
            id: b64(credential.id),
            rawId: b64(credential.id),
            type: 'public-key',
            response: {
                clientDataJSON: this.clientData(
                    'webauthn.create',
                    ceremony.challenge ?? options.challenge,
                    ceremony.origin,
                ),
                attestationObject: b64(attestationObject),
                transports: [
                    'internal',
                    'hybrid',
                ],
            },
            authenticatorAttachment: 'platform',
            clientExtensionResults: {},
        }
    }

    /**
     * An assertion with the newest credential (or the one named), as a
     * discoverable passkey answers: its user handle included.
     */
    assert(
        options: PublicKeyCredentialRequestOptionsJSON,
        ceremony: Ceremony & {
            credentialId?: string
            /** Report this counter instead of the next one. */
            counter?: number
            /** Report another user handle, or none. */
            userHandle?: string | null
        } = {},
    ): AuthenticationResponseJSON {
        const credential = ceremony.credentialId
            ? this.credentials.find(c => b64(c.id) === ceremony.credentialId)
            : this.credentials.at(-1)
        if (!credential) throw new Error('no credential on this authenticator')
        if (this.traits.counting) credential.counter += 1
        const counter = ceremony.counter ?? credential.counter
        const rpId = ceremony.rpId ?? options.rpId ?? credential.rpId
        const authData = Buffer.concat([
            sha256(rpId),
            Buffer.from([
                this.flags(ceremony),
            ]),
            u32(counter),
        ])
        const clientDataJSON = this.clientData('webauthn.get', ceremony.challenge ?? options.challenge, ceremony.origin)
        const signature = sign(
            'sha256',
            Buffer.concat([
                authData,
                sha256(Buffer.from(clientDataJSON, 'base64url')),
            ]),
            credential.privateKey,
        )
        const userHandle =
            ceremony.userHandle === undefined ? credential.userHandle : (ceremony.userHandle ?? undefined)
        return {
            id: b64(credential.id),
            rawId: b64(credential.id),
            type: 'public-key',
            response: {
                authenticatorData: b64(authData),
                clientDataJSON,
                signature: b64(signature),
                ...(userHandle
                    ? {
                          userHandle,
                      }
                    : {}),
            },
            authenticatorAttachment: 'platform',
            clientExtensionResults: {},
        }
    }

    private flags(ceremony: Ceremony) {
        const synced = this.traits.synced ? BE | BS : 0
        return UP | (ceremony.userVerified === false ? 0 : UV) | synced
    }

    private clientData(type: string, challenge: string, origin = TEST_ORIGIN) {
        return b64(
            JSON.stringify({
                type,
                challenge,
                origin,
                crossOrigin: false,
            }),
        )
    }
}
