<?php
function identity($payload) {
    return $payload;
}
function emit() {
    $msg = identity("status: ok");
    $fh = fopen("/tmp/out.log", "w");
    fwrite($fh, $msg);
    fclose($fh);
}
