// .env from .env.example with fresh local secrets: an ES256 key and random tokens.
import { generateKeyPairSync, randomBytes } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'

if (existsSync('.env')) {
    console.log('.env already exists')
    process.exit(0)
}
const { privateKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
})
const pem = privateKey
    .export({
        type: 'pkcs8',
        format: 'pem',
    })
    .toString()
    .trim()
    .replaceAll('\n', '\\n')
const token = () => randomBytes(32).toString('base64url')
const values = {
    SIGNING_KEY_PEM: `"${pem}"`,
    LOGIN_CODE_PEPPER: token(),
    NOTIFICATIONS_INTERNAL_TOKEN: token(),
    INTERNAL_API_TOKEN: token(),
}
const env = readFileSync('.env.example', 'utf8').replace(/^([A-Z_]+)=$/gm, (line, key) =>
    key in values ? `${key}=${values[key]}` : line,
)
writeFileSync('.env', env, {
    mode: 0o600,
})
console.log(
    'created .env with local secrets (NOTIFICATIONS_INTERNAL_TOKEN must match INTERNAL_API_TOKEN of notifications-api)',
)
