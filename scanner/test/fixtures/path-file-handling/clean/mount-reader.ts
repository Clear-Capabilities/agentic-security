import fs from "node:fs";
import fsPromises from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import path from "node:path";

export class MountReader {
  constructor(private readonly root: string) {}

  async read(relative: string): Promise<Buffer> {
    const target = path.resolve(this.root, relative);
    const handle = await openVerified({ root: this.root, target });
    try {
      return await handle.readFile();
    } finally {
      await handle.close();
    }
  }
}

async function openVerified(params: { root: string; target: string }): Promise<FileHandle> {
  const realRoot = await fsPromises.realpath(params.root);
  const handle = await fsPromises.open(params.target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  const stats = await handle.stat();
  if (!stats.isFile() || stats.nlink > 1) {
    await handle.close();
    throw new Error("not a regular file");
  }
  const realTarget = await fsPromises.realpath(params.target);
  if (!realTarget.startsWith(realRoot + path.sep)) {
    await handle.close();
    throw new Error("outside root");
  }
  return handle;
}
