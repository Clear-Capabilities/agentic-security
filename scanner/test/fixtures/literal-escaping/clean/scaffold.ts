export function testLines(opts: { label: string }): string[] {
  return [`assertEqual(widget.label(), ${JSON.stringify(opts.label)});`];
}

export function literal(s: string): string {
  return `"${s.replace(/[\\"]/g, '\\$&')}"`;
}

export function message(name: string): string {
  return `could not call open("${name}")`;
}
