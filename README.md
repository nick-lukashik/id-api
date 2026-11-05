# id-api

Identity of the nick-lukashik platform:
- users;
- sign-in by email code, with Google and with passkeys;
- sessions with rotating refresh tokens, one per site;
- sign-in codes for the platform's other sites (authorization code with PKCE);
- access tokens (ES256, JWKS);
- staff roles by hand; paid plans of services (grants) from subscriptions.

Built from [`nest-example`](https://github.com/nick-lukashik/nest-example): Postgres, Redis, RabbitMQ outbox. The design and the flows between the services: [`.github/docs/identity.md`](https://github.com/nick-lukashik/.github/blob/master/docs/identity.md).

Only `id-web` (server side) and other services inside the cluster call it. It has no public route.

## API (`/api/v1`)

| Route                                                                                                                             | Who                     | What                                                                                                                                                                                                                                                                                                   |
| --------------------------------------------------------------------------------------------------------------------------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `POST /login/email` `{ email, locale }`                                                                                           | id-web                  | Sends a 6-digit code through notifications-api. 202 `{ challengeId, expiresAt, resendAfter, deliveryStatus }`, the same for known and unknown emails                                                                                                                                                   |
| `POST /login/email/verify` `{ challengeId, code }`                                                                                | id-web                  | Consumes the code once, creates the user on the first sign-in, opens a session. 200 `{ accessToken, accessExpiresAt, refreshToken, sessionId, user }`; 422 `details[0].message`: `invalid_code`, `expired`, `too_many_attempts`                                                                        |
| `POST /sessions/refresh` `{ refreshToken }`                                                                                       | id-web                  | Rotates. The previous token within 20 s gets the same new token; an older one ends the session (`REUSE`, 401); one that was never issued or is older than the cap ends nothing (`DEAD`, 401). See Tokens                                                                                               |
| `POST /sessions/logout` `{ refreshToken }`                                                                                        | id-web                  | Ends the session and its children, by a token that still opens it (the current one, or the previous within 20 s). 204. Any other well-formed token also gets 204 and ends nothing, and a session id alone ends nothing; a malformed one is a 400                                                       |
| `GET /me`, `PATCH /me` `{ displayName?, locale? }`                                                                                | access token            | Profile, roles, grants; `GET` also `active`: whether the session is still alive, null when that cannot be told                                                                                                                                                                                         |
| `GET /me/sessions`, `DELETE /me/sessions/:id`, `POST /me/sessions/revoke-others`                                                  | access token            | The caller's own live sessions (see Tokens): most recently active first, 50 to a page (`?cursor=`, `nextCursor`)                                                                                                                                                                                       |
| `GET /me/session`                                                                                                                 | access token            | Whether the session of this token is alive, `{ active }`, from Redis: the token stays valid until it expires. 503 when it cannot tell                                                                                                                                                                  |
| `GET /login/google/config`                                                                                                        | id-web                  | Whether Google sign-in is on, its authorization endpoint, client id and callback                                                                                                                                                                                                                       |
| `POST /login/google` `{ code, codeVerifier, nonce, locale }`                                                                      | id-web                  | Exchanges the code at Google, checks the ID token, opens a session (a new user for a new Google account whose address Google hosts: Gmail or Workspace). 422 `unverified` for any other new address: its first sign-in is by the email code. 409 `link_required` when the email has an account already |
| `GET /me/identities`, `POST /me/identities/google`, `DELETE /me/identities/google`                                                | access token            | Linked Google account: list, link (the same body as sign-in), unlink. Linking needs a sign-in at most `PASSKEY_FRESH_SIGN_IN_MS` old (403 `reauthentication_required`)                                                                                                                                 |
| `POST /login/passkey/options`, `POST /login/passkey/verify` `{ challengeId, response }`                                           | id-web                  | Sign-in with any passkey of this RP; 422 `stale`, `unknown`, `rejected`                                                                                                                                                                                                                                |
| `GET /me/passkeys`, `POST /me/passkeys/options`, `POST /me/passkeys` `{ challengeId, name, response }`, `DELETE /me/passkeys/:id` | access token            | The caller's passkeys. Adding one needs a sign-in at most `PASSKEY_FRESH_SIGN_IN_MS` old (403 `reauthentication_required`)                                                                                                                                                                             |
| `GET /oauth/clients/:id?redirectUri=`                                                                                             | id-web                  | Whether a site and its exact callback are registered (`OAUTH_CLIENTS`)                                                                                                                                                                                                                                 |
| `POST /oauth/authorize` `{ clientId, redirectUri, codeChallenge, codeChallengeMethod }`                                           | access token            | A 60-second one-time code for the caller, for that site. Only a live id-web session gets one: 403 for a site's session, 401 for one that has ended                                                                                                                                                     |
| `POST /oauth/token` `{ grantType, clientId, redirectUri, code, codeVerifier }`                                                    | the site's server       | The code and the PKCE verifier for the site's own session (`client_id`); a failed try spends the code                                                                                                                                                                                                  |
| `GET /internal/users/:id`                                                                                                         | service token           | Email, language and status (for notifications-api)                                                                                                                                                                                                                                                     |
| `GET /.well-known/jwks.json`                                                                                                      | everyone in the cluster | Public keys of access tokens (outside `/api`)                                                                                                                                                                                                                                                          |

Limits:
- one code per email per `LOGIN_RESEND_COOLDOWN_MS` (60 s) and 10 codes per email per day;
- 20 codes per IP per hour and 30 verifications per IP per 10 minutes;
- 5 attempts per code;
- a code lives 10 minutes.

The sign-in limits fail closed (`src/login/rate-limiter.ts`). With Redis down, slow or refusing writes, sign-in answers 503, sends no code and readiness fails (the `rate-limits` check). Each refused request counts in `rate_limit_fail_open_total`; the warning goes to the log at most once per 10 s. The common throttler (`src/common`) shares that counter but stays open: it lets requests through.

Only an HMAC of the code is stored, keyed by `LOGIN_CODE_PEPPER`. The code itself goes to notifications-api in one synchronous call and nowhere else.

## Tokens

- **Access token.** JWT ES256 with `typ: at+jwt` and `kid` = RFC 7638 thumbprint. Claims: `iss` = `TOKEN_ISSUER`, `aud` = `TOKEN_AUDIENCE`, `sub`, `sid`, `roles`, `av`. Lifetime `ACCESS_TOKEN_TTL_SECONDS` (300). Services check it with [`@nick-lukashik/auth`](https://github.com/nick-lukashik/packages).
- **Refresh token.** `<sessionId>.<random>`. Only its SHA-256 is kept, in Redis (`rt:<sid>`). It rotates in one Lua script (`src/sessions/refresh-store.ts`). Redis is a required dependency here: readiness fails without it. `rtg:<sid>` keeps the previous token for the grace window (`REFRESH_GRACE_MS`, 20 s), and `rtp:<sid>` the hashes of the newest 512 superseded tokens (about 42 hours of constant use). A presented token is one of:
  - the current one: it rotates;
  - the previous one within grace: the same new token again (two tabs, a lost response);
  - `REUSE`, a superseded one still in `rtp:<sid>`: all keys go and the session is revoked (`reuse_detected`), 401;
  - `DEAD`, anything else (revoked, expired, never issued, or superseded so long ago that the cap dropped it): 401 and nothing changes, so a session id alone (the `sid` claim) burns nothing.
- **Key rotation.**
  1. Put the next public JWK into `PREVIOUS_PUBLIC_KEYS` and deploy.
  2. Switch `SIGNING_KEY_PEM` to the next key.
  3. After 5 minutes, drop the old JWK.
- **The first owner.** That person signs in once, then: `kubectl exec deploy/id-api -- node dist/cli/grant-owner.js <email>`.
- **Paid plans (grants).** A subscription gives a plan of a service, `service:plan` (`roulette:vip`), from `pay.subscription.changed.v1` (queue `id-api.subscriptions`): one row of `grants` per subscription, valid until `valid_until`; a version not newer than the last one changes nothing. Any number at once. Access tokens carry the ones in force as `grants`, so a period that ran out needs no job: the next token (5 minutes at the latest) simply lacks it. Services check `hasGrant(caller, 'roulette', 'vip')` of `@nick-lukashik/auth`. Roles are only for staff (`owner`, `support`) and never bought.
- **Sign-out.** Sites under the platform's domain share one session through the cookie, so they have no session of their own. A site on another domain signs in by a code: its session is a child of the id-web session it signed in from (`sessions.parent_session_id`). Ending a session ends its children too, so "Sign out" anywhere signs out of every site of that browser. There is one level only: a code is issued to an id-web session alone, and a session found under a site's session ends at its next refresh; "Sign out everywhere else" keeps this browser's sites. `POST /sessions/logout` takes the token itself: any token the session was given and still remembers (the newest 512 superseded ones) ends it, so a thief who turned a stolen token on is out too. A session id alone ends nothing.
- **The session list.** `GET /me/sessions` and "Sign out everywhere else" work on the live set: sessions not ended and refreshed within the refresh lifetime. Past it the Redis family has expired, though nobody marked the row. Each row says `current`, or `thisBrowser` for a site signed in from the caller's session.

## Retention

An hourly pass on every replica (`src/retention/retention.ts`) deletes sign-in data past its period, in batches that each commit by themselves:
- a sign-in code request (`login_challenges`, the email in clear): 24 hours after it was made;
- a signed-out or revoked session: 90 days after it ended;
- a session nobody ended: 90 days after its refresh token expired (last activity + `REFRESH_TOKEN_TTL_SECONDS`, 30 days);
- a sign-in code of another site (`authorization_codes`): 1 day after it expired.

The privacy policy quotes these periods: change them together.

## Passkeys and Google

- **Passkeys.** SimpleWebAuthn (`src/passkeys/`). RP `WEBAUTHN_RP_ID` (`nick-lukashik.com`), origin `WEBAUTHN_ORIGIN` (id-web) only, user verification required, discoverable credentials, ES256 / EdDSA / RS256. A challenge lives 5 minutes in Redis and is taken once (`GETDEL`). The user handle is the 16 bytes of the user id; a sign-in whose handle names another account is refused. The signature counter has to grow unless the device does not count (synced passkeys say 0).
- **Google.** `src/identities/`. The code is exchanged with the client secret and PKCE verifier; the ID token is checked against Google's JWKS (`iss`, `aud`, RS256, `nonce`), and only a verified email signs up. Off while `GOOGLE_CLIENT_ID` or `GOOGLE_CLIENT_SECRET` is empty. An empty `GOOGLE_REDIRECT_URI` falls back to the production callback.
- The email code always stays, so a passkey can be removed and Google unlinked at any time.

## Commands

```bash
pnpm install
pnpm infra:up      # Postgres, Redis, RabbitMQ (compose.yaml, ports 5441, 6391, 5681)
pnpm env:local     # .env with a fresh ES256 key and local secrets
pnpm db:migrate
pnpm dev           # http://localhost:4100
pnpm verify        # biome, typecheck, build, tests (Testcontainers)
pnpm messaging:replay-dlq id-api.subscriptions --limit 100   # dead letters back to their queue, after the cause is fixed
```

`@nick-lukashik/auth` and `@nick-lukashik/contracts` are published versions from GitHub Packages (`.npmrc`). `pnpm install` and the Docker build need a token for them: "Installing" in `packages/README.md`.

## Events

| Event                                   | When                                                       |
| --------------------------------------- | ---------------------------------------------------------- |
| `id.user.registered.v1`                 | The first sign-in of an email, in its transaction (outbox) |
| consumed: `pay.subscription.changed.v1` | The paid plan (grant) of a subscription (inbox)            |
