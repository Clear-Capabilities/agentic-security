<?php
// Synthetic fixture: one method of four applies the guard. A minority habit
// is not a convention, so the other three are not deviations.
namespace App\Http\Controllers;

class BannerController
{
    private $storage;

    public function a($filename, $contents)
    {
        $this->assertSafeFilename($filename);
        $this->storage->store("banners", $filename, $contents);
    }

    public function b($filename, $contents)
    {
        $this->storage->store("banners", $filename, $contents);
    }

    public function c($filename, $contents)
    {
        $this->storage->store("banners", $filename, $contents);
    }

    public function d($filename, $contents)
    {
        $this->storage->store("banners", $filename, $contents);
    }
}
