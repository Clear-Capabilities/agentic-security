<?php
class HelloController {
  public function hello(Request $request) {
    return new Response('<p>Hello ' . htmlspecialchars($request->query->get('name')) . '</p>');
  }
}