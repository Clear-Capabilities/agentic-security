// Fails on the benign control, so the hostile input is never reached.
export function parse() {
  throw new Error('parser is broken');
}
