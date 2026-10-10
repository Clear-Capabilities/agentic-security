<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
class UsersController extends Controller {
  public function find(Request $request) {
    $name = $request->input('name');
    return DB::select(DB::raw("SELECT * FROM users WHERE name='" . $name . "'"));
  }
}
