<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class GreetController extends Controller
{
    public function show(Request $request)
    {
        $who = $request->input('who');
        return response('<h1>Hi ' . e($who) . '</h1>');
    }
}
