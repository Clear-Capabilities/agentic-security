export async function GET(request: Request) {
  const id = new URL(request.url).searchParams.get('id');
  const upstream = await fetch('https://api.internal.test/lookup', { method: 'POST', body: JSON.stringify({ id }) });
  return new Response(await upstream.text());
}
