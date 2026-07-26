<?php
function identity($payload) {
    return $payload;
}
function emit() {
    $cmd = identity("status: ok");
    exec($cmd);
}
