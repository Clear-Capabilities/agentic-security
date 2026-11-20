<?php

const MAX_TOTAL = 52428800;

function import_archive()
{
    $zip = new ZipArchive();
    $zip->open($_FILES['archive']['tmp_name']);
    $total = 0;
    for ($i = 0; $i < $zip->numFiles; $i++) {
        $total += $zip->statIndex($i)['size'];
    }
    if ($total > MAX_TOTAL) {
        return;
    }
    $zip->extractTo('/srv/imports');
    $zip->close();
}

function parse_feed()
{
    $doc = new DOMDocument();
    $doc->loadXML($_POST['feed']);
    return $doc;
}
