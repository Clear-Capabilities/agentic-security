import { NextRequest, NextResponse } from 'next/server';
import { execFile } from 'child_process';
export async function GET(request: NextRequest) {
  const host = request.nextUrl.searchParams.get('host');
  execFile('ping', ['-c', '1', host]);
  return NextResponse.json({ ok: true });
}