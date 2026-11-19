<?php

function banner()
{
    $width = $_GET['width'];
    echo str_repeat('=', $width);
}

function slots()
{
    $count = (int) $_POST['count'];
    $slots = array_fill(0, $count, null);
    return count($slots);
}

function unique_ids()
{
    $ids = $_POST['ids'];
    $out = [];
    foreach ($ids as $id) {
        if (!in_array($id, $out)) {
            $out[] = $id;
        }
    }
    return $out;
}
