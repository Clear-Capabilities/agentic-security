<?php
function emit($payload) {
    $fh = fopen("/tmp/out.log", "w");
    fwrite($fh, $payload);
    fclose($fh);
}
