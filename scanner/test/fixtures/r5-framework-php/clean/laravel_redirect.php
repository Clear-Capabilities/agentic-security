<?php
class AuthController {
  public function after(Request $request) {
    return redirect('/home');
  }
}