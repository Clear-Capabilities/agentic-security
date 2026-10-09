// The handler fails on every call, so the payload is never delivered to anything.
export function handler() {
  throw new Error('handler is broken');
}
