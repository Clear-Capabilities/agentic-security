<?php
function verify($request) {
    $signature = $request['x-signature'];
    $expected_hmac = hash_hmac('sha256', $request['body'], getenv('K'));
    return hash_equals($expected_hmac, $signature);
}
