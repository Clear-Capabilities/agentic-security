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
        $name ??= $this->getLabel();
        $target = rtrim($dir, '/') . '/' . $name;
        return move_uploaded_file($this->tmpPath, $target);
    }
}

function save_avatar(string $dir): bool
{
    $clientName = $_FILES['avatar']['name'];
    return move_uploaded_file($_FILES['avatar']['tmp_name'], $dir . '/' . $clientName);
}

function extension_ok(string $filename): bool
{
    $deniedExtensions = ['php', 'phtml', 'phar'];
    foreach ($deniedExtensions as $ext) {
        if (str_ends_with(strtolower($filename), '.' . $ext)) {
            return false;
        }
    }
    return true;
}

function is_inside_base(string $file, string $base): bool
{
    $realFile = realpath($file);
    $realBase = realpath($base);
    return strpos($realFile, $realBase) === 0;
}
