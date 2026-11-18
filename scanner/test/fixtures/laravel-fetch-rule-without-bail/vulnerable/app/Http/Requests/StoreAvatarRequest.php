<?php

namespace App\Http\Requests;

use App\Rules\PublicDestination;
use App\Rules\ServesImage;
use Illuminate\Foundation\Http\FormRequest;

class StoreAvatarRequest extends FormRequest
{
    public function rules(): array
    {
        return [
            'avatar_url' => [
                'required',
                'url',
                new PublicDestination(),
                new ServesImage(),
            ],
            'caption' => ['nullable', 'string'],
        ];
    }
}
