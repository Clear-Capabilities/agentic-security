import { NextRequest, NextResponse } from 'next/server';
import { exec } from 'child_process';
export async function GET(request: NextRequest) {
  const host = request.nextUrl.searchParams.get('host');
  exec('ping -c 1 ' + host);
  return NextResponse.json({ ok: true });
}