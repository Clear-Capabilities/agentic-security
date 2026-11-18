export function testLines(opts: { label: string }): string[] {
  return [`assertEqual(widget.label(), "${opts.label}");`];
}

export function literal(s: string): string {
  return `"${s.replace(/"/g, '\\"')}"`;
}
