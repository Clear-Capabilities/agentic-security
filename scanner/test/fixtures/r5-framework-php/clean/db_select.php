<?php
class UserController {
  public function find(Request $request) {
    return DB::select('SELECT * FROM users WHERE name = ?', [$request->input('name')]);
  }
}