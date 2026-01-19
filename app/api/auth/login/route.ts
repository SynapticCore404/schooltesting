import { NextResponse } from 'next/server'
import { ADMIN_COOKIE_NAME, ADMIN_SESSION_TTL_SECONDS, createAdminSessionToken, getAdminPassword } from '@/lib/auth'

export const runtime = 'nodejs'

export async function GET() {
  const password = getAdminPassword()
  if (!password && process.env.NODE_ENV === 'production') {
    return NextResponse.json({ error: 'Server sozlanmagan' }, { status: 500 })
  }
  const expected = password || 'teacher123'
  return NextResponse.json({ length: expected.length })
}

export async function POST(req: Request) {
  const { password } = await req.json().catch(() => ({ password: '' }))
  const adminPassword = getAdminPassword()
  if (!adminPassword && process.env.NODE_ENV === 'production') {
    return NextResponse.json({ error: 'Server sozlanmagan' }, { status: 500 })
  }
  const expected = adminPassword || 'teacher123'
  if (typeof password !== 'string' || password !== expected) {
    return NextResponse.json({ error: 'Noto‘g‘ri parol' }, { status: 401 })
  }

  const token = createAdminSessionToken(expected)
  const res = NextResponse.json({ ok: true })
  const protocol = (() => { try { return new URL(req.url).protocol } catch { return 'http:' } })()
  res.cookies.set(ADMIN_COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: protocol === 'https:',
    path: '/',
    maxAge: ADMIN_SESSION_TTL_SECONDS,
  })
  return res
}
