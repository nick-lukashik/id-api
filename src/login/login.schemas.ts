import { localeSchema } from '@nick-lukashik/contracts'
import { z } from 'zod'

export const requestCodeSchema = z.object({
    email: z.email().max(254),
    locale: localeSchema.default('en'),
})
export type RequestCode = z.infer<typeof requestCodeSchema>

export const verifyCodeSchema = z.object({
    challengeId: z.uuid(),
    code: z.string().regex(/^[0-9]{6}$/, 'six digits'),
})
export type VerifyCode = z.infer<typeof verifyCodeSchema>

export const refreshSchema = z.object({
    refreshToken: z.string().min(40).max(200),
})
export type RefreshInput = z.infer<typeof refreshSchema>

export const updateProfileSchema = z
    .object({
        displayName: z.string().trim().min(1).max(80).nullable().optional(),
        locale: localeSchema.optional(),
    })
    .refine(value => value.displayName !== undefined || value.locale !== undefined, 'nothing to change')
export type UpdateProfile = z.infer<typeof updateProfileSchema>
