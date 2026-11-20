<?php

function import_archive()
{
    $zip = new ZipArchive();
    $zip->open($_FILES['archive']['tmp_name']);
    $zip->extractTo('/srv/imports');
    $zip->close();
}

function parse_feed()
{
    $doc = new DOMDocument();
    $doc->loadXML($_POST['feed'], LIBXML_PARSEHUGE);
    return $doc;
}
