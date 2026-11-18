import { resolve, join } from 'path';

export class Workspace {
  private readonly root: string;

  constructor(root: string) {
    this.root = resolve(root);
  }

  locate(rel: string): string | null {
    const target = resolve(join(this.root, rel));
    if (!target.startsWith(this.root)) return null;
    return target;
  }
}
