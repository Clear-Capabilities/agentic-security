<?php

const MAX_WIDTH = 120;

function banner()
{
    $width = (int) $_GET['width'];
    if ($width > MAX_WIDTH) {
        $width = MAX_WIDTH;
    }
    echo str_repeat('=', $width);
}

function slots()
{
    $count = min((int) $_POST['count'], 1000);
    $slots = array_fill(0, $count, null);
    return count($slots);
}

function unique_ids()
{
    $ids = $_POST['ids'];
    $out = [];
    foreach ($ids as $id) {
        $out[$id] = true;
    }
    return array_keys($out);
}
