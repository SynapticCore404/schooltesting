import { NextResponse } from 'next/server'
import { isAdminRequestAuthenticated } from '@/lib/auth'

export const runtime = 'nodejs'

export async function GET() {
  return NextResponse.json({ authed: isAdminRequestAuthenticated() })
}
