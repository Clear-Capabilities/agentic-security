<?php
class ProxyController {
  public function fetch(Request $request) {
    return Http::get('https://api.internal.test/items', ['q' => $request->input('q')]);
  }
}