<?php
// Synthetic fixture: upload() and replace() reject unsafe file names before
// storing, import() stores the caller's name as it came.
namespace App\Http\Controllers;

class AvatarController
{
    private $storage;

    public function upload($userId, $filename, $contents)
    {
        $this->assertSafeFilename($filename);
        $this->storage->store("avatars/" . $userId, $filename, $contents);
        return ['ok' => true];
    }

    public function replace($userId, $filename, $contents)
    {
        $this->assertSafeFilename($filename);
        $this->storage->delete("avatars/" . $userId);
        $this->storage->store("avatars/" . $userId, $filename, $contents);
        return ['ok' => true];
    }

    public function import($userId, $filename, $contents)
    {
        $this->storage->store("avatars/" . $userId, $filename, $contents);
        return ['ok' => true];
    }

    private function assertSafeFilename($filename)
    {
        if (strpos($filename, '..') !== false || strpos($filename, '/') !== false) {
            throw new \InvalidArgumentException('unsafe file name');
        }
    }
}
