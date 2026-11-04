# AGENTS.md

id-api: users, sign-in by email code, sessions (refresh tokens in Redis), ES256 access tokens and JWKS, roles. Built from nest-example; `src/common/` is the shared infrastructure and stays identical to the examples (only `app-error.ts`, `error.filter.ts` and `openapi.ts` carry the extra status codes UNAUTHORIZED, FORBIDDEN, CONFLICT, UNPROCESSABLE). Human docs: `README.md`, design: `nick-lukashik/.github` `docs/identity.md`.

## Commands

- `pnpm install`, `pnpm infra:up`, `pnpm env:local`, `pnpm db:migrate`, `pnpm dev`.
- `pnpm verify`: lint + typecheck + build + test. It must be green before you hand work over.
- `pnpm db:generate --name <what_it_changes>` after a change to `src/db/schema.ts`; read the SQL.

## Rules

- Never log, store or publish a sign-in code, a refresh token or a key. Only `challengeId` and `sessionId` appear in logs.
- A code is compared in constant time and consumed atomically. Session revocation always deletes the Redis family first, then marks the row.
- Every role change bumps `users.access_version` in the same transaction.
- Routes of the caller's own data use `@Authenticated()` and `@Caller()`; in-cluster routes use `@Internal()`. Nothing trusts headers other than the bearer token.
