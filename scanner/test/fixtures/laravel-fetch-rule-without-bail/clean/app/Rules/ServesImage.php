<?php

namespace App\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Support\Facades\Http;

class ServesImage implements ValidationRule
{
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $response = Http::timeout(5)->head((string) $value);
        if (!str_starts_with((string) $response->header('Content-Type'), 'image/')) {
            $fail('The :attribute does not serve an image.');
        }
    }
}
