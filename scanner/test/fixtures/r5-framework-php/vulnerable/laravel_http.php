<?php
class ProxyController {
  public function fetch(Request $request) {
    return Http::get($request->input('url'));
  }
}