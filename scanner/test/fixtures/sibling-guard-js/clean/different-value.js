// Synthetic fixture: the guard is applied to a DIFFERENT value (the label),
// so it says nothing about the URL; and the one unvalidated URL post has no
// guarded population to deviate from.
import { validateLabel } from './labels.js';

export class FeedService {
  constructor(client) {
    this.client = client;
  }

  async addFeed(label, url) {
    validateLabel(label);
    return this.client.post(url, { label });
  }

  async renameFeed(label, url) {
    validateLabel(label);
    return this.client.post(url, { label });
  }

  async touchFeed(label, url) {
    return this.client.post(url, { touch: true });
  }
}
