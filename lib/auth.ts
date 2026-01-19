import { cookies } from 'next/headers'
import { createHmac, timingSafeEqual } from 'crypto'

export const ADMIN_COOKIE_NAME = 't_auth'
export const ADMIN_SESSION_TTL_SECONDS = 60 * 60 * 8

type TokenPayload = {
  exp: number
}

function resolveAdminPassword(): string | null {
  const envPassword = process.env.ADMIN_PASSWORD
  if (typeof envPassword === 'string' && envPassword.length > 0) return envPassword
  if (process.env.NODE_ENV !== 'production') return 'teacher123'
  return null
}

function signPayload(payloadB64: string, secret: string) {
  return createHmac('sha256', secret).update(payloadB64).digest('base64url')
}

function timingSafeMatch(a: string, b: string) {
  const aBuf = Buffer.from(a)
  const bBuf = Buffer.from(b)
  if (aBuf.length !== bBuf.length) return false
  try {
    return timingSafeEqual(aBuf, bBuf)
  } catch {
    return false
  }
}

export function createAdminSessionToken(secret: string): string {
  const payload: TokenPayload = { exp: Math.floor(Date.now() / 1000) + ADMIN_SESSION_TTL_SECONDS }
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url')
  const signature = signPayload(payloadB64, secret)
  return `${payloadB64}.${signature}`
}

export function validateAdminToken(token: string, secret: string): boolean {
  const [payloadB64, signature] = token.split('.')
  if (!payloadB64 || !signature) return false
  const expectedSig = signPayload(payloadB64, secret)
  if (!timingSafeMatch(signature, expectedSig)) return false
  try {
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8')) as TokenPayload
    if (typeof payload.exp !== 'number') return false
    return payload.exp > Math.floor(Date.now() / 1000)
  } catch {
    return false
  }
}

export function getAdminPassword(): string | null {
  return resolveAdminPassword()
}

export function isAdminRequestAuthenticated(): boolean {
  const password = resolveAdminPassword()
  if (!password) return false
  const token = cookies().get(ADMIN_COOKIE_NAME)?.value
  if (!token) return false
  return validateAdminToken(token, password)
}
