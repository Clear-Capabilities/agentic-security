<?php

class IncomingFile
{
    protected $tmpPath;
    protected $originalName;
    protected $label;

    public function __construct(string $tmpPath, string $originalName)
    {
        $this->tmpPath = $tmpPath;
        $this->label = $originalName;
        $this->originalName = $originalName;
    }

    public function getLabel(): string
    {
        return $this->label;
    }

    public function store(string $dir, ?string $name = null): bool
    {
        if ($name === null) {
            $name = basename($this->getLabel());
        }
        $target = rtrim($dir, '/') . '/' . $name;
        return move_uploaded_file($this->tmpPath, $target);
    }
}

function save_avatar(string $dir): bool
{
    $stored = bin2hex(random_bytes(16)) . '.png';
    return move_uploaded_file($_FILES['avatar']['tmp_name'], $dir . '/' . $stored);
}

function extension_ok(string $filename): bool
{
    $deniedExtensions = ['php', 'phtml', 'phar'];
    foreach (explode('.', strtolower($filename)) as $segment) {
        if (in_array($segment, $deniedExtensions, true)) {
            return false;
        }
    }
    return true;
}

function is_inside_base(string $file, string $base): bool
{
    $realFile = realpath($file);
    $realBase = realpath($base);
    $prefix = rtrim($realBase, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    return $realFile === $realBase || strpos($realFile, $prefix) === 0;
}
