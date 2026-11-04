import type { Request } from 'express'

/** Who is calling, as far as id-web forwarded it: for rate limits and the sessions list. */
export type ClientContext = {
    ip: string | null
    userAgent: string | null
}

export function clientContext(request: Request): ClientContext {
    const userAgent = request.headers['user-agent']
    return {
        // req.ip follows TRUST_PROXY_HOPS: id-web sets x-forwarded-for from Traefik's real-ip.
        ip: request.ip ?? null,
        userAgent: typeof userAgent === 'string' ? userAgent.slice(0, 300) : null,
    }
}
