import { NextResponse } from 'next/server'
import { ADMIN_COOKIE_NAME } from '@/lib/auth'

export async function POST(req: Request) {
  const res = NextResponse.json({ ok: true })
  const protocol = (() => { try { return new URL(req.url).protocol } catch { return 'http:' } })()
  res.cookies.set(ADMIN_COOKIE_NAME, '', {
    httpOnly: true,
    sameSite: 'lax',
    secure: protocol === 'https:',
    path: '/',
    maxAge: 0,
  })
  return res
}
