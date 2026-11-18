<?php
function loadPayload(string $raw): string
{
    $out = gzdecode($raw);
    return $out === false ? '' : $out;
}
