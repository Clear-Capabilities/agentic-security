<?php
function verify($request) {
    $signature = $request['x-signature'];
    $expected_hmac = hash_hmac('sha256', $request['body'], getenv('K'));
    if ($signature === $expected_hmac) {
        return true;
    }
    return false;
}
