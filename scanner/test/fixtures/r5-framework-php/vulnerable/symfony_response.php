<?php
class HelloController {
  public function hello(Request $request) {
    return new Response('<p>Hello ' . $request->query->get('name') . '</p>');
  }
}