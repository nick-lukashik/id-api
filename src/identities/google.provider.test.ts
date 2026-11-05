import { describe, expect, it } from 'vitest'
import { googleHostsEmail } from './google.provider.js'

describe('googleHostsEmail', () => {
    it('trusts Gmail and a Workspace domain, and no other address', () => {
        expect(googleHostsEmail('person@gmail.com', undefined)).toBe(true)
        expect(googleHostsEmail('person@company.example', 'company.example')).toBe(true)
        expect(googleHostsEmail('person@company.example', undefined)).toBe(false)
        expect(googleHostsEmail('person@gmail.com.evil.example', undefined)).toBe(false)
        expect(googleHostsEmail(null, undefined)).toBe(false)
    })
})
