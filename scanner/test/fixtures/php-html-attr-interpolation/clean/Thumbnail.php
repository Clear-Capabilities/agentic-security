<?php

class Thumbnail
{
    public function render($record, $size)
    {
        $src = htmlspecialchars($this->resolve($record->photo), ENT_QUOTES);
        $size = (int) $size;
        return "<img src='$src' width='$size' />";
    }

    public function caption($text)
    {
        return sprintf("<img alt='%s' />", e($text));
    }
}
