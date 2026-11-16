// The factory fails before it returns a request listener, so no request is ever served and no verdict can be formed.
export function createApp() {
  throw new Error('configuration missing');
}
