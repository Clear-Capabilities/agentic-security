import fsPromises from "node:fs/promises";
import path from "node:path";

export class MountReader {
  constructor(private readonly root: string) {}

  async read(relative: string): Promise<Buffer> {
    const target = path.resolve(this.root, relative);
    await assertNoSymlinkEscape({ root: this.root, target });
    return await fsPromises.readFile(target);
  }
}

async function assertNoSymlinkEscape(params: { root: string; target: string }): Promise<void> {
  const realRoot = await fsPromises.realpath(params.root);
  const stats = await fsPromises.lstat(params.target);
  if (stats.isSymbolicLink()) {
    throw new Error("symlink refused");
  }
  const realTarget = await fsPromises.realpath(params.target);
  if (!realTarget.startsWith(realRoot + path.sep)) {
    throw new Error("outside root");
  }
}
