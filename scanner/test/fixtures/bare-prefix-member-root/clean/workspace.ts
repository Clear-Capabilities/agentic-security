import { resolve, join, sep } from 'path';

export class Workspace {
  private readonly root: string;

  constructor(root: string) {
    this.root = resolve(root);
  }

  locate(rel: string): string | null {
    const target = resolve(join(this.root, rel));
    if (target !== this.root && !target.startsWith(this.root + sep)) return null;
    return target;
  }
}
