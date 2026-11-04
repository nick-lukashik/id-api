# id-api

Identity of the nick-lukashik platform:
- users;
- sign-in by email code, with Google and with passkeys;
- sessions with rotating refresh tokens, one per site;
- sign-in codes for the platform's other sites (authorization code with PKCE);
- access tokens (ES256, JWKS);
- roles: staff by hand, paid from subscriptions.

Built from [`nest-example`](https://github.com/nick-lukashik/nest-example): Postgres, Redis, RabbitMQ outbox. The design and the flows between the services: [`.github/docs/identity.md`](https://github.com/nick-lukashik/.github/blob/master/docs/identity.md).

Only `id-web` (server side) and other services inside the cluster call it. It has no public route.

## API (`/api/v1`)

| Route                                                                            | Who                     | What                                                                                                                                                                                                                            |
| -------------------------------------------------------------------------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /login/email` `{ email, locale }`                                          | id-web                  | Sends a 6-digit code through notifications-api. 202 `{ challengeId, expiresAt, resendAfter, deliveryStatus }`, the same for known and unknown emails                                                                            |
| `POST /login/email/verify` `{ challengeId, code }`                               | id-web                  | Consumes the code once, creates the user on the first sign-in, opens a session. 200 `{ accessToken, accessExpiresAt, refreshToken, sessionId, user }`; 422 `details[0].message`: `invalid_code`, `expired`, `too_many_attempts` |
| `POST /sessions/refresh` `{ refreshToken }`                                      | id-web                  | Rotates. The previous token within 20 s gets the same new token; an older one ends the session (401)                                                                                                                            |
| `POST /sessions/logout` `{ refreshToken }`                                       | id-web                  | Ends the session. 204                                                                                                                                                                                                           |
| `GET /me`, `PATCH /me` `{ displayName?, locale? }`                               | access token            | Profile and roles                                                                                                                                                                                                               |
| `GET /me/sessions`, `DELETE /me/sessions/:id`, `POST /me/sessions/revoke-others` | access token            | The caller's own sessions                                                                                                                                                                                                       |
| `GET /login/google/config`                                                       | id-web                  | Whether Google sign-in is on, its authorization endpoint, client id and callback                                                                                                                                                |
| `POST /login/google` `{ code, codeVerifier, nonce, locale }`                     | id-web                  | Exchanges the code at Google, checks the ID token, opens a session (a new user for a new Google account). 409 `link_required` when the email has an account already                                                            |
| `GET /me/identities`, `POST /me/identities/google`, `DELETE /me/identities/google` | access token          | Linked Google account: list, link (the same body as sign-in), unlink                                                                                                                                                             |
| `POST /login/passkey/options`, `POST /login/passkey/verify` `{ challengeId, response }` | id-web           | Sign-in with any passkey of this RP; 422 `stale`, `unknown`, `rejected`                                                                                                                                                         |
| `GET /me/passkeys`, `POST /me/passkeys/options`, `POST /me/passkeys` `{ challengeId, name, response }`, `DELETE /me/passkeys/:id` | access token | The caller's passkeys. Adding one needs a sign-in at most `PASSKEY_FRESH_SIGN_IN_MS` old (403 `reauthentication_required`) |
| `GET /oauth/clients/:id?redirectUri=`                                            | id-web                  | Whether a site and its exact callback are registered (`OAUTH_CLIENTS`)                                                                                                                                                          |
| `POST /oauth/authorize` `{ clientId, redirectUri, codeChallenge, codeChallengeMethod }` | access token     | A 60-second one-time code for the caller, for that site                                                                                                                                                                          |
| `POST /oauth/token` `{ grantType, clientId, redirectUri, code, codeVerifier }`   | the site's server       | The code and the PKCE verifier for the site's own session (`client_id`); a failed try spends the code                                                                                                                           |
| `GET /internal/users/:id`                                                        | service token           | Email, language and status (for notifications-api)                                                                                                                                                                              |
| `GET /.well-known/jwks.json`                                                     | everyone in the cluster | Public keys of access tokens (outside `/api`)                                                                                                                                                                                   |

Limits:
- one code per email per `LOGIN_RESEND_COOLDOWN_MS` (60 s) and 10 codes per email per day;
- 20 codes and 30 verifications per IP per hour;
- 5 attempts per code;
- a code lives 10 minutes.

Only an HMAC of the code is stored, keyed by `LOGIN_CODE_PEPPER`. The code itself goes to notifications-api in one synchronous call and nowhere else.

## Tokens

- **Access token.** JWT ES256 with `typ: at+jwt` and `kid` = RFC 7638 thumbprint. Claims: `iss` = `TOKEN_ISSUER`, `aud` = `TOKEN_AUDIENCE`, `sub`, `sid`, `roles`, `av`. Lifetime `ACCESS_TOKEN_TTL_SECONDS` (300). Services check it with [`@nick-lukashik/auth`](https://github.com/nick-lukashik/packages).
- **Refresh token.** `<sessionId>.<random>`. Only its SHA-256 is kept, in Redis (`rt:<sid>`). It rotates in one Lua script (`src/sessions/refresh-store.ts`). Redis is a required dependency here: readiness fails without it.
- **Key rotation.**
  1. Put the next public JWK into `PREVIOUS_PUBLIC_KEYS` and deploy.
  2. Switch `SIGNING_KEY_PEM` to the next key.
  3. After 5 minutes, drop the old JWK.
- **The first owner.** That person signs in once, then: `kubectl exec deploy/id-api -- node dist/cli/grant-owner.js <email>`.
- **Paid roles.** `subscriber` comes only from `pay.subscription.changed.v1` (queue `id-api.subscriptions`): one row of `role_bindings` per subscription, valid until `expires_at`; a version not newer than the last one changes nothing. The CLI grants staff roles only.

## Passkeys and Google

- **Passkeys.** SimpleWebAuthn (`src/passkeys/`). RP `WEBAUTHN_RP_ID` (`nick-lukashik.com`), origin `WEBAUTHN_ORIGIN` (id-web) only, user verification required, discoverable credentials, ES256 / EdDSA / RS256. A challenge lives 5 minutes in Redis and is taken once (`GETDEL`). The user handle is the 16 bytes of the user id; a sign-in whose handle names another account is refused. The signature counter has to grow unless the device does not count (synced passkeys say 0).
- **Google.** `src/identities/`. The code is exchanged with the client secret and PKCE verifier; the ID token is checked against Google's JWKS (`iss`, `aud`, RS256, `nonce`), and only a verified email signs up. Off while `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` or `GOOGLE_REDIRECT_URI` is empty.
- The email code always stays, so a passkey can be removed and Google unlinked at any time.

## Commands

```bash
pnpm install
pnpm infra:up      # Postgres, Redis, RabbitMQ (compose.yaml, ports 5441, 6391, 5681)
pnpm env:local     # .env with a fresh ES256 key and local secrets
pnpm db:migrate
pnpm dev           # http://localhost:4100
pnpm verify        # biome, typecheck, build, tests (Testcontainers)
```

`@nick-lukashik/auth` and `@nick-lukashik/contracts` come from the neighbouring `packages` folder (`file:`) until their first publish. The Docker build needs the published versions (`packages/README.md`).

## Events

| Event                   | When                                                       |
| ----------------------- | ---------------------------------------------------------- |
| `id.user.registered.v1` | The first sign-in of an email, in its transaction (outbox) |
| consumed: `pay.subscription.changed.v1` | The paid role of a subscription (inbox) |
