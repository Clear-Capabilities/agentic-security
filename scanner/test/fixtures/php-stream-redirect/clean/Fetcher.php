<?php
class Fetcher
{
    public static function fetch(string $url, array $allowedHosts): ?string
    {
        $host = parse_url($url, PHP_URL_HOST) ?? '';
        if (!in_array($host, $allowedHosts, true)) {
            return null;
        }
        $options = [
            'http' => [
                'timeout' => 5,
                'follow_location' => 0,
            ],
        ];
        $ctx = stream_context_create($options);
        $body = @file_get_contents($url, false, $ctx);
        return $body === false ? null : $body;
    }
}
