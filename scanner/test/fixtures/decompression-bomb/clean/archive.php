<?php
function loadPayload(string $raw, int $limit): string
{
    $out = gzdecode($raw, $limit);
    return $out === false ? '' : $out;
}
