// Synthetic fixture: two methods validate the webhook URL before posting to
// it, updateHook() posts the caller's URL as it came.
import { validateWebhookUrl } from './net-guard.js';

export class WebhookService {
  constructor(client, store) {
    this.client = client;
    this.store = store;
  }

  async createHook(owner, url) {
    validateWebhookUrl(url);
    const hook = { owner, url };
    await this.store.save(hook);
    return this.client.post(url, { ping: true });
  }

  async testHook(url) {
    validateWebhookUrl(url);
    return this.client.post(url, { test: true });
  }

  async updateHook(id, url) {
    const hook = await this.store.load(id);
    hook.url = url;
    return this.client.post(url, { ping: true });
  }
}
