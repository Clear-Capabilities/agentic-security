// A "fix" that refuses every request: nothing leaks, and nothing legitimate works either.
export function createApp() {
  return (req, res) => { res.writeHead(403).end(); };
}
