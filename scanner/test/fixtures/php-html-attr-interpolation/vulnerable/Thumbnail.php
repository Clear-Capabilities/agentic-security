<?php

class Thumbnail
{
    public function render($record, $size)
    {
        $src = $this->resolve($record->photo);
        return "<img src='$src' width='$size' />";
    }
}
