<?php

namespace App\Http\Controllers;

use App\Models\Member;
use Illuminate\Http\Request;

class MemberLookupController extends Controller
{
    public function check(Request $request)
    {
        $this->authorize('invite', Member::class);

        $member = Member::findByEmail($request->input('email'));

        return ['exists' => $member !== null];
    }
}
