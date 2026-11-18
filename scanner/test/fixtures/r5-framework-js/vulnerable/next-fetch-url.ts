export async function GET(request: Request) {
  const target = new URL(request.url).searchParams.get('target');
  const upstream = await fetch(target);
  return new Response(await upstream.text());
}